import base64
import datetime
import json
import os
import re
import uuid
from typing import Iterable

import graphene
import requests
from django.core.exceptions import ValidationError

from ....checkout import AddressType
from ....checkout.checkout_cleaner import (
    clean_checkout_shipping,
    validate_checkout_email,
)
from ....checkout.complete_checkout import complete_checkout
from ....checkout.error_codes import CheckoutErrorCode
from ....checkout.fetch import (
    CheckoutInfo,
    CheckoutLineInfo,
    fetch_checkout_info,
    fetch_checkout_lines,
)
from ....checkout.utils import is_shipping_required
from ....core import analytics
from ....checkout import models as checkout_models
from ....order import models as order_models
from ....permission.enums import AccountPermissions
from ...account.i18n import I18nMixin
from ...app.dataloaders import get_app_promise
from ...core import ResolveInfo
from ...core.descriptions import ADDED_IN_34, ADDED_IN_38, DEPRECATED_IN_3X_INPUT
from ...core.doc_category import DOC_CATEGORY_CHECKOUT
from ...core.fields import JSONString
from ...core.mutations import BaseMutation
from ...core.scalars import UUID
from ...core.types import CheckoutError, NonNullList
from ...core.validators import validate_one_of_args_is_in_mutation
from ...discount.dataloaders import load_discounts
from ...meta.mutations import MetadataInput
from ...order.types import Order
from ...plugins.dataloaders import get_plugin_manager_promise
from ...site.dataloaders import get_site_promise
from ...utils import get_user_or_app_from_context
from ..types import Checkout
from .utils import get_checkout
from saleor.product import models as product_models
from saleor.order import models as order_models
from saleor.checkout import models as checkout_models
from saleor.clc import models as clc_models
from saleor.payment import models as payment_models
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def encrypt(plain_text, HashKey, HashIV):
    cipher = Cipher(algorithms.AES(HashKey), modes.CBC(HashIV), backend=default_backend())
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text) + padder.finalize()

    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(cipher_text).decode('utf-8')


class CheckoutComplete(BaseMutation, I18nMixin):
    order = graphene.Field(Order, description="Placed order.")
    confirmation_needed = graphene.Boolean(
        required=True,
        default_value=False,
        description=(
            "Set to true if payment needs to be confirmed"
            " before checkout is complete."
        ),
    )
    confirmation_data = JSONString(
        required=False,
        description=(
            "Confirmation data used to process additional authorization steps."
        ),
    )

    class Arguments:
        id = graphene.ID(
            description="The checkout's ID." + ADDED_IN_34,
            required=False,
        )
        token = UUID(
            description=f"Checkout token.{DEPRECATED_IN_3X_INPUT} Use `id` instead.",
            required=False,
        )
        checkout_id = graphene.ID(
            required=False,
            description=(
                f"The ID of the checkout. {DEPRECATED_IN_3X_INPUT} Use `id` instead."
            ),
        )
        store_source = graphene.Boolean(
            default_value=False,
            description=(
                "Determines whether to store the payment source for future usage. "
                f"{DEPRECATED_IN_3X_INPUT} Use checkoutPaymentCreate for this action."
            ),
        )
        redirect_url = graphene.String(
            required=False,
            description=(
                "URL of a view where users should be redirected to "
                "see the order details. URL in RFC 1808 format."
            ),
        )
        payment_data = JSONString(
            required=False,
            description=(
                "Client-side generated data required to finalize the payment."
            ),
        )
        metadata = NonNullList(
            MetadataInput,
            description=(
                    "Fields required to update the checkout metadata." + ADDED_IN_38
            ),
            required=False,
        )

    class Meta:
        description = (
            "Completes the checkout. As a result a new order is created and "
            "a payment charge is made. This action requires a successful "
            "payment before it can be performed. "
            "In case additional confirmation step as 3D secure is required "
            "confirmationNeeded flag will be set to True and no order created "
            "until payment is confirmed with second call of this mutation."
        )
        doc_category = DOC_CATEGORY_CHECKOUT
        error_type_class = CheckoutError
        error_type_field = "checkout_errors"

    @classmethod
    def validate_checkout_addresses(
            cls,
            checkout_info: CheckoutInfo,
            lines: Iterable[CheckoutLineInfo],
    ):
        """Validate checkout addresses.

        Mutations for updating addresses have option to turn off a validation. To keep
        consistency, we need to validate it. This will confirm that we have a correct
        address and we can finalize a checkout. In case when address fields
        normalization was turned off, we apply it here.
        Raises ValidationError when any address is not correct.
        """
        shipping_address = checkout_info.shipping_address
        billing_address = checkout_info.billing_address

        if is_shipping_required(lines):
            clean_checkout_shipping(checkout_info, lines, CheckoutErrorCode)
            if shipping_address:
                shipping_address_data = shipping_address.as_data()
                cls.validate_address(
                    shipping_address_data,
                    address_type=AddressType.SHIPPING,
                    format_check=True,
                    required_check=True,
                    enable_normalization=True,
                    instance=shipping_address,
                )
                if shipping_address_data != shipping_address.as_data():
                    shipping_address.save()

        if not billing_address:
            raise ValidationError(
                {
                    "billing_address": ValidationError(
                        "Billing address is not set",
                        code=CheckoutErrorCode.BILLING_ADDRESS_NOT_SET.value,
                    )
                }
            )
        billing_address_data = billing_address.as_data()
        cls.validate_address(
            billing_address_data,
            address_type=AddressType.BILLING,
            format_check=True,
            required_check=True,
            enable_normalization=True,
            instance=billing_address,
        )
        if billing_address_data != billing_address.as_data():
            billing_address.save()

    @classmethod
    def perform_mutation(  # type: ignore[override]
            cls,
            _root,
            info: ResolveInfo,
            /,
            *,
            checkout_id=None,
            id=None,
            metadata=None,
            payment_data=None,
            redirect_url=None,
            store_source,
            token=None,
    ):

        is_vrc = False
        checkout_token = base64.b64decode(str(id).encode("utf-8")).decode("utf-8").split(":")[1]
        CheckoutLines = checkout_models.CheckoutLine.objects.filter(checkout_id=checkout_token)
        payment_gateway_obj = payment_models.Payment.objects.filter(checkout_id=checkout_token).first()
        if payment_gateway_obj:
            # 只有需要付款訂單才會在checkoutComplete產生payment，也才需要檢查訂單內有無要擋住電信卡
            payment_gateway = payment_gateway_obj.gateway
            for CheckoutLine in CheckoutLines:
                prod_type_name = product_models.ProductVariant.objects.get(id=CheckoutLine.variant.id).product.product_type.name
                if prod_type_name == 'storeValueCard':
                    if payment_gateway == "saleor.payments.cashOnDelivery":
                        raise ValidationError(
                            {
                                "vrc_cellphone": ValidationError(
                                    "電信卡類別不能貨到付款",
                                )
                            }
                        )
            # 只有需要付款訂單才會在checkoutComplete產生payment，也才需要發票
            idata = payment_data["invoice"]
            _type = ""
            _name = ""
            _email = ""
            _donate = ""
            _personal_type = ""
            _personal_carrierNumber = ""
            _company_uniNumber = ""
            _company_address = ""
            exception_data = ""
            clc_models.Invoice.objects.create(
                checkout_no=checkout_token,
                type=_type,
                name=_name,
                email=_email,
                donate=_donate,
                personal_type=_personal_type,
                personal_carrierNumber=_personal_carrierNumber,
                company_uniNumber=_company_uniNumber,
                company_address=_company_address,
                invoice_data=json.dumps(idata),
                exception_data=exception_data
            )

        vrc_varint_sku = None
        for CheckoutLine in CheckoutLines:
            ProductVariant = product_models.ProductVariant.objects.get(id=CheckoutLine.variant.id)
            vrc_varint_sku = ProductVariant.sku
            product_id = ProductVariant.product_id
            # 確認類別名稱
            category_name = product_models.Product.objects.get(id=product_id).category.name
            if category_name == '遠傳儲值卡':
                is_vrc = True
                break
        vrc_cellphone = None
        if payment_data.get("vrc_cellphone") is not None:
            vrc_cellphone = payment_data["vrc_cellphone"]
        if is_vrc:
            if vrc_cellphone is not None:
                # 定義台灣手機號碼的正則表達式
                pattern = r'^09\d{8}$'
                # 使用正則表達式進行驗證
                if re.match(pattern, vrc_cellphone):
                    pass
                else:
                    raise ValidationError(
                        {
                            "vrc_cellphone": ValidationError(
                                "手機格式錯誤",
                            )
                        }
                    )
            else:
                raise ValidationError(
                    {
                        "vrc_cellphone": ValidationError(
                            "手機號碼是空的",
                        )
                    }
                )
            is_testing = os.environ.get('clc_is_testing', '1')
            if is_testing == '1':
                url = 'https://61.61.135.144/vrc/VrcService/Storedvalidation'
            else:
                url = 'https://vrc.arcoa.com.tw/vrc/VrcService/Storedvalidation'

            key = b"ptWadzG6WfLMs7fi"
            iv = b"ptWadzG6WfLMs7fi"
            account = "01AC0170C"
            pwd = "25970099"

            if is_testing == '1':
                data = {
                    "Account": encrypt(account.encode('utf-8'), key, iv),
                    "Password": encrypt(pwd.encode('utf-8'), key, iv),
                    "PhoneNumber": vrc_cellphone,
                    "FETOfferID": vrc_varint_sku
                }
            else:
                data = {
                    "Account": encrypt(account.encode('utf-8'), key, iv),
                    "Password": encrypt(pwd.encode('utf-8'), key, iv),
                    "PhoneNumber": vrc_cellphone,
                    "FETOfferID": vrc_varint_sku
                }
            if is_testing == '1':
                r = requests.post(url, json=data, headers={'APIKEY': 'a5brc8xqy9u3t2fk'}, verify=False)
            else:
                r = requests.post(url, json=data, headers={'APIKEY': 'a5brc8xqy9u3t2fk'})
            response_data = json.loads(r.content.decode())
            print(response_data)
            ReturnCode = response_data.get('ReturnCode')
            ReturnMsg = response_data.get('ReturnMsg')
            if ReturnCode != '0000':
                raise ValidationError("%s_%s" % ("遠傳電信卡", ReturnMsg))

        # 中華電信卡
        for CheckoutLine in CheckoutLines:
            ProductVariant = product_models.ProductVariant.objects.get(id=CheckoutLine.variant.id)
            product_id = ProductVariant.product_id
            # 確認類別名稱
            category_name = product_models.Product.objects.get(id=product_id).category.name
            if category_name == '中華儲值卡':
                # 確認數量、sku對應so
                store_value_qty = CheckoutLine.quantity
                varint_sku = ProductVariant.sku
                storeValueCard_objs = clc_models.storeValueCard.objects.filter(so=varint_sku, card_status=0)
                if store_value_qty > len(storeValueCard_objs):
                    raise ValidationError(
                        {
                            "vrc_cellphone": ValidationError(
                                "中華電信卡庫存不足",
                            )
                        }
                    )
                for storeValueCard_obj in storeValueCard_objs[0:int(store_value_qty)]:
                    storeValueCard_obj.card_status = 1
                    storeValueCard_obj.order_id = checkout_token
                    storeValueCard_obj.updated = datetime.datetime.now()
                    storeValueCard_obj.save()
            if category_name == '遠傳儲值卡':
                store_value_qty = CheckoutLine.quantity
                clc_models.VrcOrderList.objects.create(
                    checkout_token=checkout_token,
                    variant=ProductVariant,
                    quantity=store_value_qty,
                    cellphone=vrc_cellphone)

        if payment_data.get("combo") is not None:
            c_id = uuid.UUID(str(base64.b64decode(id)).split(":")[1].replace("'", ""))
            for combo in payment_data["combo"]:
                variant_id = str(base64.b64decode(combo["id"])).split(":")[1].replace("'", "")
                qty = combo["qty"]
                currency_ = combo['currency']
                check_out = checkout_models.CheckoutLine.objects.create(quantity=qty, checkout_id=c_id, variant_id=variant_id, currency=currency_, tax_rate=0, total_price_gross_amount=0, total_price_net_amount=0)
                check_out.save()
        validate_one_of_args_is_in_mutation(
            "checkout_id", checkout_id, "token", token, "id", id
        )
        tracking_code = analytics.get_client_id(info.context)

        try:
            checkout = get_checkout(
                cls, info, checkout_id=checkout_id, token=token, id=id
            )
        except ValidationError as e:
            # DEPRECATED
            if id or checkout_id:
                id = id or checkout_id
                token = cls.get_global_id_or_error(
                    id, only_type=Checkout, field="id" if id else "checkout_id"
                )

            order = order_models.Order.objects.get_by_checkout_token(token)
            if order:
                if not order.channel.is_active:
                    raise ValidationError(
                        {
                            "channel": ValidationError(
                                "Cannot complete checkout with inactive channel.",
                                code=CheckoutErrorCode.CHANNEL_INACTIVE.value,
                            )
                        }
                    )
                # The order is already created. We return it as a success
                # checkoutComplete response. Order is anonymized for not logged in
                # user
                return CheckoutComplete(
                    order=order, confirmation_needed=False, confirmation_data={}
                )
            raise e
        if metadata is not None:
            cls.check_metadata_permissions(
                info,
                id or checkout_id or graphene.Node.to_global_id("Checkout", token),
            )
            cls.validate_metadata_keys(metadata)

        # validate_checkout_email(checkout)

        manager = get_plugin_manager_promise(info.context).get()
        lines, unavailable_variant_pks = fetch_checkout_lines(checkout)
        if unavailable_variant_pks:
            not_available_variants_ids = {
                graphene.Node.to_global_id("ProductVariant", pk)
                for pk in unavailable_variant_pks
            }
            raise ValidationError(
                {
                    "lines": ValidationError(
                        "Some of the checkout lines variants are unavailable.",
                        code=CheckoutErrorCode.UNAVAILABLE_VARIANT_IN_CHANNEL.value,
                        params={"variants": not_available_variants_ids},
                    )
                }
            )
        if not lines:
            raise ValidationError(
                {
                    "lines": ValidationError(
                        "Cannot complete checkout without lines.",
                        code=CheckoutErrorCode.NO_LINES.value,
                    )
                }
            )
        discounts = load_discounts(info.context)
        checkout_info = fetch_checkout_info(checkout, lines, discounts, manager)

        cls.validate_checkout_addresses(checkout_info, lines)

        requestor = get_user_or_app_from_context(info.context)
        if requestor and requestor.has_perm(AccountPermissions.IMPERSONATE_USER):
            # Allow impersonating user and process a checkout by using user details
            # assigned to checkout.
            customer = checkout.user
        else:
            customer = info.context.user

        site = get_site_promise(info.context).get()

        order, action_required, action_data = complete_checkout(
            manager=manager,
            checkout_info=checkout_info,
            lines=lines,
            payment_data=payment_data or {},
            store_source=store_source,
            discounts=discounts,
            user=customer,
            app=get_app_promise(info.context).get(),
            site_settings=site.settings,
            tracking_code=tracking_code,
            redirect_url=redirect_url,
            metadata_list=metadata,
        )

        # If gateway returns information that additional steps are required we need
        # to inform the frontend and pass all required data
        return CheckoutComplete(
            order=order,
            confirmation_needed=action_required,
            confirmation_data=action_data,
        )
