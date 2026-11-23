POST请求：
localhost:9898/data-security/api/asymmetricTSC/encrypt-client-key

请求数据application/json：
```html
{
    "publicKey": "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAERtKLZS2r3LSSIxyMrk4lmTia51VeJJuBNUzKYSUeooOHAv6DSU9WuQf6BZx7e4Pq8D62SLRNrB4Lrrw/4R2/iA==",
    "clientKey":"0123456789abcdeffedcba7896543210"
}
```


返回数据：
```html
{
"data": "BNbWI/dsZD6RvTeMzcsUaGHnDJquyezOlcizN0h9iArzZn7zHQX30Wp/ySaknrPs8kEnPTGD+8Kkh7GvO5WtAJss1hIL/l8ypRMO9NeIdGFwKayPYPN7qjnnbQj7q64L6gLaNQD2A6dvpvjqu7Q59U43+PMLqfXd459/0jVMpOZR"
}
```