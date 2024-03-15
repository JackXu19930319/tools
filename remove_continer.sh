docker stop $(docker ps -a -q)
docker rm $(docker ps -a -q)
docker rmi $(docker images -q)

# chmod +x remove_continer.sh
# ./remove_continer.sh