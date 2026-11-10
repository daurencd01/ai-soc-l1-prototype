# Демонстрационные сценарии

Источник каталога — [`backend/app/scenarios.py`](../backend/app/scenarios.py). Он доступен через `/api/scenarios` и страницу «Демонстрационные сценарии». `expected_classification`, `expected_verdict` и `expected_action` — критерии проверки из каталога, а не поля, передаваемые анализатору как доказательства. Сценарии создают синтетические события только в DEMO.

В каталоге **34 сценария, один из них — `FP`**: `root_parser_false_positive`. Алерт заявляет успешный вход root, но отдельное событие Splunk с тем же `event_id` подтверждает отказ. Его `expected_action=manual_review` описывает настройки по умолчанию: `AUTO_CLOSE_ENABLED=false`, поэтому автоматического закрытия нет. Для демонстрации автозакрытия нужно **до запуска сценария** создать и отдельно утвердить действующую FP-политику для `root_ssh` с точным совпадением `host`, `src_ip`, `auth_method`, включить `AUTO_CLOSE_ENABLED=true` и установить уровень, разрешающий действие (`controlled_automation`, `auto_close` или `approved_response`). Ручное закрытие администратором допускается при действующей политике и уровне `controlled_automation` или `approved_response` даже при выключенном глобальном флаге. Закрытие в DEMO симулируется; базовый адаптер Splunk в CONNECTED не поддерживает закрытие алерта. Подтверждённая согласованная активность остаётся `BENIGN_TRUE_POSITIVE`, а повторные ошибки известного IPsec peer — `NOISE`; оба класса идут на проверку, а не в FP-закрытие. Создание кейса для `TP` зависит от разрешённого уровня действий и состояния симулятора TheHive.

| Сценарий | `expected_classification` | `expected_verdict` | `expected_action` |
| --- | --- | --- | --- |
| `root_approved` | `BENIGN_TRUE_POSITIVE` | `needs_review` | `manual_review` |
| `root_unapproved` | `TP` | `true_positive` | `create_case` |
| `root_missing_context` | `INCONCLUSIVE` | `needs_review` | `manual_review` |
| `root_parser_false_positive` | `FP` | `false_positive` | `manual_review` |
| `root_expired_exception` | `INCONCLUSIVE` | `needs_review` | `manual_review` |
| `vpn_new_country` | `TP` | `true_positive` | `create_case` |
| `vpn_site_to_site_allowed` | `BENIGN_TRUE_POSITIVE` | `needs_review` | `manual_review` |
| `vpn_handshake_only` | `INCONCLUSIVE` | `needs_review` | `manual_review` |
| `vpn_ip_in_user_field` | `INCONCLUSIVE` | `needs_review` | `manual_review` |
| `ipsec_configuration_failure` | `NOISE` | `needs_review` | `manual_review` |
| `ipsec_unknown_peer_burst` | `INCONCLUSIVE` | `needs_review` | `manual_review` |
| `ipsec_failure_then_success` | `TP` | `true_positive` | `create_case` |
| `bruteforce_success` | `TP` | `true_positive` | `create_case` |
| `confirmed_test_incident` | `TP` | `true_positive` | `create_case` |
| `bruteforce_distributed` | `TP` | `true_positive` | `create_case` |
| `bruteforce_approved_test` | `BENIGN_TRUE_POSITIVE` | `needs_review` | `manual_review` |
| `powershell_encoded` | `TP` | `true_positive` | `create_case` |
| `powershell_approved_admin` | `BENIGN_TRUE_POSITIVE` | `needs_review` | `manual_review` |
| `powershell_missing_parent` | `INCONCLUSIVE` | `needs_review` | `manual_review` |
| `unknown_rule` | `INCONCLUSIVE` | `needs_review` | `manual_review` |
| `duplicate_delivery` | `BENIGN_TRUE_POSITIVE` | `needs_review` | `one_alert_no_close` |
| `linked_alerts` | `TP` | `true_positive` | `one_case` |
| `splunk_unavailable` | `INCONCLUSIVE` | `needs_review` | `integration_degraded` |
| `thehive_unavailable` | `TP` | `true_positive` | `case_failed` |
| `misp_unavailable` | `INCONCLUSIVE` | `needs_review` | `integration_degraded` |
| `llm_error` | `INCONCLUSIVE` | `needs_review` | `manual_review` |
| `prompt_injection_log` | `TP` | `true_positive` | `create_case` |
| `late_event` | `INCONCLUSIVE` | `needs_review` | `manual_review` |
| `worker_restart` | `TP` | `true_positive` | `one_case` |
| `uncertain_action` | `TP` | `true_positive` | `reconcile_case` |
| `tenant_isolation` | `INCONCLUSIVE` | `needs_review` | `cross_tenant_forbidden` |
| `private_ip_only` | `INCONCLUSIVE` | `needs_review` | `manual_review` |
| `misp_no_hit_only` | `INCONCLUSIVE` | `needs_review` | `manual_review` |
| `failure_only` | `INCONCLUSIVE` | `needs_review` | `manual_review` |

`manual_review` означает передачу аналитику без автоматического закрытия при настройках сценария по умолчанию; дополнительные условия для FP описаны выше. `create_case` — запрос на симулированное создание кейса при разрешающей политике. `one_alert_no_close` проверяет дедупликацию двух доставок одного `source_event_id`; `one_case` — один кейс для связанных алертов или после восстановления worker. `integration_degraded` требует проверить недоступность источника и сохранённое доказательство сбоя. `case_failed` требует убедиться, что внешний кейс не отмечен успешно созданным при ошибке TheHive; точный статус локальной записи действия проверяется в журнале. `reconcile_case` требует сверки неопределённого результата до повтора. `cross_tenant_forbidden` требует отдельной проверки доступа из двух учётных записей.

После запуска проверяйте фактические алерты, доказательства, решения, переходы состояний, действия и кейсы в карточке расследования. Для `worker_restart` действительно остановите worker после постановки алерта и запустите снова: запуск сценария сам по себе не моделирует рестарт. Для `tenant_isolation` создайте алерт от имени второго заказчика и попробуйте прочитать его ID под учётной записью первого; отказ должен подтвердить отдельный API-тест.
