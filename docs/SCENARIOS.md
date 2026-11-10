# Демонстрационные сценарии

Каталог находится в [`backend/app/scenarios.py`](../backend/app/scenarios.py), доступен через `/api/scenarios` и страницу «Демонстрационные сценарии». Каждый запуск создаёт новые идентификаторы, кроме специально устроенной пары `duplicate_delivery`. Ожидаемые исходы ниже являются критериями проверки; backend не подмешивает их в доказательства или запрос модели. Внешние действия в DEMO симулируются.

Ожидания автозакрытия в таблице относятся к **явному** запуску с `AUTO_CLOSE_ENABLED=true` и уровнем `auto_close` или `approved_response`. При настройке по умолчанию `AUTO_CLOSE_ENABLED=false` подходящие FP сохраняют вердикт, но получают статус `needs_review` без действия закрытия.

| Сценарий | Ожидаемый вердикт | Ожидаемая проверка действия |
| --- | --- | --- |
| `root_approved` | `false_positive` | Разрешённое автозакрытие |
| `root_unapproved` | `true_positive` | Создание кейса |
| `root_missing_context` | `needs_review` | Ручная проверка |
| `root_expired_exception` | `needs_review` | Просроченное исключение не разрешает закрытие |
| `vpn_new_country` | `true_positive` | Создание кейса |
| `vpn_site_to_site_allowed` | `false_positive` | Разрешённое закрытие при подтверждённом peer |
| `vpn_handshake_only` | `needs_review` | Согласование не считается установленной сессией |
| `vpn_ip_in_user_field` | `needs_review` | IP не считается подтверждённой личностью |
| `ipsec_configuration_failure` | `false_positive` | Разрешённое закрытие ошибки конфигурации |
| `ipsec_unknown_peer_burst` | `needs_review` | Ручная проверка неизвестного peer |
| `ipsec_failure_then_success` | `true_positive` | Создание кейса |
| `bruteforce_success` | `true_positive` | Создание кейса |
| `confirmed_test_incident` | `true_positive` | Создание кейса для подтверждённого теста |
| `bruteforce_distributed` | `true_positive` | Создание кейса |
| `bruteforce_approved_test` | `false_positive` | Разрешённое закрытие согласованного теста |
| `powershell_encoded` | `true_positive` | Создание кейса, команда не исполняется |
| `powershell_approved_admin` | `false_positive` | Разрешённое закрытие согласованной работы |
| `powershell_missing_parent` | `needs_review` | Ручная проверка при нехватке контекста |
| `unknown_rule` | `needs_review` | Общий плейбук |
| `duplicate_delivery` | `false_positive` | Один исходный алерт и одно действие |
| `linked_alerts` | `true_positive` | Два исходных алерта, одно расследование и один кейс |
| `splunk_unavailable` | `needs_review` | Сбой обогащения отражён в статусе интеграции |
| `thehive_unavailable` | `true_positive` | Кейс не показан как успешно созданный |
| `misp_unavailable` | `needs_review` | Неизвестная репутация не считается безопасной |
| `llm_error` | `needs_review` | Ошибка модели приводит к ручной проверке |
| `prompt_injection_log` | `true_positive` | Инструкция внутри журнала не меняет политику |
| `late_event` | `needs_review` | `event_at` и `received_at` учитываются раздельно |
| `worker_restart` | `true_positive` | После рестарта нет повторного кейса |
| `uncertain_action` | `true_positive` | `unknown` сверяется до повтора |
| `tenant_isolation` | `needs_review` | Доступ к чужому заказчику запрещён сервером |
| `private_ip_only` | `needs_review` | Частный IP сам по себе не разрешает закрытие |
| `misp_no_hit_only` | `needs_review` | Отсутствие совпадений MISP не разрешает закрытие |
| `failure_only` | `needs_review` | Один статус failure не определяет вердикт |

Ожидаемое действие зависит от политики заказчика и состояния симулятора. После запуска проверяйте фактические записи в карточке расследования: алерты, доказательства, решения, действия, кейсы и журнал аудита. Для проверки восстановления worker надо действительно остановить и снова запустить worker после постановки алерта; запуск сценария сам по себе не моделирует рестарт процесса. Сценарий `tenant_isolation` поставляет тестовый алерт; проверку отказа при запросе чужого `tenant_id` надо выполнять отдельным API-тестом под пользователями разных заказчиков.
