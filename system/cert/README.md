# Cert bootstrap

Сервис для первоначального создания сертификатов безопасности, требуются для запуска nginx

> Для каждого устройства при первом запуске будет создан индивидуальный сертификат

## Куда положить

- api-cert -> `/usr/bin/api-cert`
- api-cert.service -> `/lib/systemd/system/api-cert.service`

> Службу нужно сделать активной по-умолчанию