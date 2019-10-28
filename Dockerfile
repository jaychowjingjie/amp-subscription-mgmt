# docker build -t image-name .
# docker run -p 80:80 -it image-name
# docker stop $(docker ps -a -q) -> stops all containers
# docker rm $(docker ps -a -q)   -> removes all containers
# docker rmi $(docker images -q) -> removes all images
# docker tag test santhosh2netdocker/test:1 -> tag docker
# docker container rm --force bb -> remove one container
# docker run -d -t -i -e REDIS_NAMESPACE='staging' -> loading env variables
# docker run  -e TENANT_ID=123 -e CLIENT_ID=123 -e CLIENT_SECRET=123 -e MARKETPLACEAPI_TENANTID=123 -e MARKETPLACEAPI_CLIENT_ID=123 -e MARKETPLACEAPI_CLIENT_SECRET=123  -p 5000:5000 -it amp:latest

FROM python
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
ENTRYPOINT ["python"]
CMD ["app.py"]