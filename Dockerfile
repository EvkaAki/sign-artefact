FROM python
WORKDIR /app
COPY . .
COPY private.pem /keys/private.pem
RUN pip install -r requirements.txt
