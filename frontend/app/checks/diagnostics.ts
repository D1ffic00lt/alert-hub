export type DiagnosticLanguage = "ru" | "en";

export type CheckDiagnostic = {
  code: string;
  title: string;
  detail: string;
  metric: string;
  action: string;
  known: boolean;
};

export type CheckErrorReasonDescription = {
  reason: string;
  label: string;
  detail: string;
  known: boolean;
};

export type CheckExecutorStateDescription = {
  state: string;
  label: string;
  known: boolean;
};

type Localized = readonly [russian: string, english: string];

type DiagnosticCopy = {
  title: Localized;
  detail: Localized;
  metric: string;
  action: Localized;
};

const REQUIRED_STATUS = "synthetic_check_status";
const REQUIRED_TIMESTAMP = "synthetic_check_last_run_timestamp_seconds";
const DURATION = "synthetic_check_duration_seconds";
const TTFB = "synthetic_check_ttfb_seconds";
const INFO = "synthetic_check_info";
const STATE = "synthetic_check_state";
const CANARY = "synthetic_check_canary_success";
const ASSERTION = "synthetic_check_egress_match";
const ASSERTION_STATE = "synthetic_check_egress_state";
const TARGET_STATUS = "synthetic_check_target_success";
const TARGET_STATE = "synthetic_check_target_state";
const ERRORS = "synthetic_check_errors_total";

function copy(
  title: Localized,
  detail: Localized,
  metric: string,
  action: Localized,
): DiagnosticCopy {
  return { title, detail, metric, action };
}

const DIAGNOSTICS: Record<string, DiagnosticCopy> = {
  missing_status: copy(
    ["Нет результата проверки", "Check result is missing"],
    [
      "Для этой комбинации Source, Scenario и Variant не получен обязательный статус.",
      "No required status was returned for this Source, Scenario, and Variant combination.",
    ],
    REQUIRED_STATUS,
    [
      "Проверьте, что исполнитель публикует статус для каждого объявленного результата.",
      "Verify that the runner publishes a status for every declared result.",
    ],
  ),
  invalid_status: copy(
    ["Статус имеет неверное значение", "Status has an invalid value"],
    [
      "Значение статуса не равно 0 или 1 либо не является конечным числом.",
      "The status is not 0 or 1, or is not a finite number.",
    ],
    REQUIRED_STATUS,
    [
      "Исправьте экспортёр: метрика должна отдавать только 0 или 1.",
      "Fix the exporter so the metric emits only 0 or 1.",
    ],
  ),
  conflicting_status: copy(
    ["Источники вернули разные статусы", "Sources returned conflicting statuses"],
    [
      "Для одного результата одновременно получены значения 0 и 1.",
      "Both 0 and 1 were returned for the same result.",
    ],
    REQUIRED_STATUS,
    [
      "Удалите дублирующиеся серии или выровняйте их labels и значения.",
      "Remove duplicate series or make their labels and values consistent.",
    ],
  ),
  missing_timestamp: copy(
    ["Нет времени последнего запуска", "Last-run time is missing"],
    [
      "Обязательная отметка времени завершённого запуска не получена.",
      "The required timestamp for the completed run was not returned.",
    ],
    REQUIRED_TIMESTAMP,
    [
      "Проверьте публикацию timestamp вместе со статусом результата.",
      "Verify that the runner publishes the timestamp with the result status.",
    ],
  ),
  invalid_timestamp: copy(
    ["Время запуска некорректно", "Run timestamp is invalid"],
    [
      "Timestamp отрицательный, нечисловой или находится слишком далеко в будущем.",
      "The timestamp is negative, non-numeric, or too far in the future.",
    ],
    REQUIRED_TIMESTAMP,
    [
      "Проверьте часы исполнителя и формат Unix timestamp в секундах.",
      "Check the runner clock and its Unix timestamp-in-seconds format.",
    ],
  ),
  conflicting_timestamp: copy(
    ["Источники вернули разное время запуска", "Sources returned conflicting run times"],
    [
      "Для одного результата получено несколько разных timestamp.",
      "Multiple timestamps were returned for the same result.",
    ],
    REQUIRED_TIMESTAMP,
    [
      "Уберите дубли серий или синхронизируйте публикацию результата.",
      "Remove duplicate series or synchronize result publication.",
    ],
  ),
  invalid_duration: copy(
    ["Duration некорректна", "Duration is invalid"],
    [
      "Продолжительность отрицательная либо не является конечным числом.",
      "The duration is negative or is not a finite number.",
    ],
    DURATION,
    [
      "Исправьте измерение duration; значение должно быть в секундах и не меньше нуля.",
      "Fix duration measurement; the value must be non-negative seconds.",
    ],
  ),
  conflicting_duration: copy(
    ["Источники вернули разные duration", "Sources returned conflicting durations"],
    [
      "Для одного результата получено несколько значений продолжительности.",
      "Multiple duration values were returned for the same result.",
    ],
    DURATION,
    [
      "Проверьте дублирующиеся серии и одинаковые наборы labels.",
      "Check for duplicate series with identical label sets.",
    ],
  ),
  invalid_ttfb: copy(
    ["TTFB некорректен", "TTFB is invalid"],
    [
      "Время до первого байта отрицательное либо не является конечным числом.",
      "Time to first byte is negative or is not a finite number.",
    ],
    TTFB,
    [
      "Исправьте измерение TTFB; значение должно быть в секундах и не меньше нуля.",
      "Fix TTFB measurement; the value must be non-negative seconds.",
    ],
  ),
  conflicting_ttfb: copy(
    ["Источники вернули разные значения TTFB", "Sources returned conflicting TTFB values"],
    [
      "Для одного результата получено несколько значений времени до первого байта.",
      "Multiple time-to-first-byte values were returned for the same result.",
    ],
    TTFB,
    [
      "Проверьте дублирующиеся серии и одинаковые наборы labels.",
      "Check for duplicate series with identical label sets.",
    ],
  ),
  invalid_info: copy(
    ["Inventory Check некорректен", "Check inventory is invalid"],
    [
      "Inventory-серия имеет значение, отличное от 1, или содержит некорректные данные.",
      "The inventory series is not 1 or contains invalid data.",
    ],
    INFO,
    [
      "Исправьте inventory-серию; объявленная комбинация должна иметь значение 1.",
      "Fix the inventory series; every declared combination must have value 1.",
    ],
  ),
  invalid_identifier: copy(
    ["Обязательный идентификатор отклонён", "A required identifier was rejected"],
    [
      "Source, Scenario или Variant не соответствует допустимому формату.",
      "A Source, Scenario, or Variant label does not match the accepted format.",
    ],
    `${REQUIRED_STATUS} / ${REQUIRED_TIMESTAMP}`,
    [
      "Используйте короткие стабильные идентификаторы без секретов, IP-адресов и UUID.",
      "Use short stable identifiers without secrets, IP addresses, or UUIDs.",
    ],
  ),
  invalid_optional_identifier: copy(
    ["Идентификатор необязательной метрики отклонён", "An optional metric identifier was rejected"],
    [
      "Labels необязательной метрики не совпадают с допустимым форматом Check.",
      "Optional metric labels do not match the accepted Check identifier format.",
    ],
    "optional synthetic_check_* metric",
    [
      "Сопоставьте Source, Scenario и Variant с обязательными сериями Check.",
      "Match Source, Scenario, and Variant to the required Check series.",
    ],
  ),
  invalid_name: copy(
    ["Имя Check отклонено", "Check name was rejected"],
    [
      "Отображаемое имя пустое, слишком длинное либо похоже на чувствительные данные.",
      "The display name is empty, too long, or resembles sensitive data.",
    ],
    "check_name label",
    [
      "Задайте короткое человекочитаемое имя без адресов и секретов.",
      "Provide a short human-readable name without addresses or secrets.",
    ],
  ),
  conflicting_name: copy(
    ["Имена Check не совпадают", "Check names conflict"],
    [
      "Серии одного Check содержат разные отображаемые имена.",
      "Series for the same Check contain different display names.",
    ],
    "check_name label",
    [
      "Используйте одно имя для одинакового check_id во всех сериях.",
      "Use one name for the same check_id across all series.",
    ],
  ),
  invalid_group: copy(
    ["Группа Check отклонена", "Check group was rejected"],
    [
      "Название группы пустое, слишком длинное либо содержит недопустимые данные.",
      "The group name is empty, too long, or contains disallowed data.",
    ],
    "group label",
    ["Задайте короткое безопасное название группы.", "Provide a short, safe group name."],
  ),
  conflicting_group: copy(
    ["Группы Check не совпадают", "Check groups conflict"],
    [
      "Серии одного Check относят его к разным группам.",
      "Series for the same Check assign it to different groups.",
    ],
    "group label",
    ["Используйте одну группу для одинакового check_id.", "Use one group for the same check_id."],
  ),
  invalid_target: copy(
    ["Target отклонён", "Target was rejected"],
    [
      "Отображаемый Target пустой, слишком длинный либо содержит недопустимые данные.",
      "The display Target is empty, too long, or contains disallowed data.",
    ],
    "target label",
    [
      "Передавайте короткое безопасное имя Target без адресов и секретов.",
      "Provide a short safe Target name without addresses or secrets.",
    ],
  ),
  conflicting_target: copy(
    ["Targets результата не совпадают", "Result Targets conflict"],
    [
      "Для одной комбинации Check получено несколько разных Target.",
      "Multiple Targets were returned for the same Check combination.",
    ],
    "target label",
    [
      "Согласуйте Target у серий с одинаковыми Source, Scenario и Variant.",
      "Use one Target for series with the same Source, Scenario, and Variant.",
    ],
  ),
  invalid_canary: copy(
    ["Canary-результат некорректен", "Canary result is invalid"],
    [
      "Идентификатор или значение canary не соответствует контракту.",
      "The canary identifier or value does not match the contract.",
    ],
    CANARY,
    [
      "Проверьте label canary и публикуйте только значение 0 или 1.",
      "Check the canary label and publish only 0 or 1.",
    ],
  ),
  conflicting_canary: copy(
    ["Canary-результаты не совпадают", "Canary results conflict"],
    [
      "Для одной canary одновременно получены разные значения.",
      "Conflicting values were returned for the same canary.",
    ],
    CANARY,
    [
      "Уберите дублирующиеся canary-серии или выровняйте их значения.",
      "Remove duplicate canary series or make their values consistent.",
    ],
  ),
  invalid_assertion: copy(
    ["Assertion-результат некорректен", "Assertion result is invalid"],
    [
      "Значение assertion не равно 0 или 1 либо не является конечным числом.",
      "The assertion is not 0 or 1, or is not a finite number.",
    ],
    ASSERTION,
    [
      "Исправьте экспортёр assertion: допустимы только значения 0 и 1.",
      "Fix the assertion exporter so it emits only 0 or 1.",
    ],
  ),
  conflicting_assertion: copy(
    ["Assertion-результаты не совпадают", "Assertion results conflict"],
    [
      "Для одного assertion одновременно получены разные значения.",
      "Conflicting values were returned for the same assertion.",
    ],
    ASSERTION,
    [
      "Уберите дублирующиеся assertion-серии или выровняйте их значения.",
      "Remove duplicate assertion series or make their values consistent.",
    ],
  ),
  invalid_target_id: copy(
    ["Идентификатор Target отклонён", "Target identifier was rejected"],
    [
      "Target-серия содержит отсутствующий или небезопасный target_id.",
      "A Target series contains a missing or unsafe target_id.",
    ],
    "target_id label",
    [
      "Задайте короткий стабильный target_id без адресов, UUID и секретов.",
      "Use a short stable target_id without addresses, UUIDs, or secrets.",
    ],
  ),
  invalid_assertion_id: copy(
    ["Идентификатор Assertion отклонён", "Assertion identifier was rejected"],
    [
      "Assertion-серия содержит небезопасный assertion_id.",
      "An assertion series contains an unsafe assertion_id.",
    ],
    "assertion_id label",
    [
      "Задайте короткий стабильный assertion_id без чувствительных данных.",
      "Use a short stable assertion_id without sensitive data.",
    ],
  ),
  invalid_state: copy(
    ["Состояние исполнителя некорректно", "Executor state is invalid"],
    [
      "Набор one-hot серий не обозначает ровно одно допустимое состояние результата.",
      "The one-hot series do not identify exactly one allowed result state.",
    ],
    STATE,
    [
      "Публикуйте значение 1 ровно для одного допустимого state, для остальных — 0.",
      "Publish 1 for exactly one allowed state and 0 for the others.",
    ],
  ),
  conflicting_state: copy(
    ["Серии состояния противоречат друг другу", "Executor-state series conflict"],
    [
      "Для одного state получены разные значения либо активны несколько состояний.",
      "One state has conflicting values, or multiple states are active.",
    ],
    STATE,
    [
      "Уберите дубли и оставьте одно активное состояние результата.",
      "Remove duplicates and leave exactly one active result state.",
    ],
  ),
  conflicting_state_status: copy(
    ["State и итоговый status не совпадают", "State and final status disagree"],
    [
      "Состояние исполнителя противоречит бинарному результату того же запуска.",
      "The executor state contradicts the binary result for the same run.",
    ],
    `${STATE} / ${REQUIRED_STATUS}`,
    [
      "Публикуйте согласованные state и status из одного завершённого запуска.",
      "Publish consistent state and status values from the same completed run.",
    ],
  ),
  conflicting_info_metadata: copy(
    [
      "Inventory-метаданные противоречат результату",
      "Inventory metadata conflicts with the result",
    ],
    [
      "Связанные info-серии дают разные Scenario, Variant или Target.",
      "Related info series provide conflicting Scenario, Variant, or Target values.",
    ],
    INFO,
    [
      "Согласуйте metadata labels для одного Check и Source.",
      "Make metadata labels consistent for the same Check and Source.",
    ],
  ),
  invalid_target_status: copy(
    ["Статус Target некорректен", "Target status is invalid"],
    ["Бинарное значение Target не равно 0 или 1.", "The Target binary value is not 0 or 1."],
    TARGET_STATUS,
    ["Публикуйте для каждого Target только 0 или 1.", "Publish only 0 or 1 for each Target."],
  ),
  conflicting_target_status: copy(
    ["Статусы Target не совпадают", "Target statuses conflict"],
    [
      "Для одного target_id получены разные бинарные результаты.",
      "Conflicting binary results were returned for one target_id.",
    ],
    TARGET_STATUS,
    [
      "Уберите дубли Target-серий или выровняйте их значения.",
      "Remove duplicate Target series or make their values consistent.",
    ],
  ),
  invalid_target_state: copy(
    ["Состояние Target некорректно", "Target state is invalid"],
    [
      "One-hot серии Target не обозначают ровно одно допустимое состояние.",
      "The Target one-hot series do not identify exactly one allowed state.",
    ],
    TARGET_STATE,
    [
      "Оставьте одно активное допустимое состояние для каждого target_id.",
      "Leave exactly one allowed active state for each target_id.",
    ],
  ),
  conflicting_target_state: copy(
    ["Состояния Target противоречат друг другу", "Target states conflict"],
    [
      "Для одного Target получены дубли или несколько активных состояний.",
      "Duplicate or multiple active states were returned for one Target.",
    ],
    TARGET_STATE,
    ["Исправьте one-hot публикацию состояния Target.", "Fix the Target one-hot state publication."],
  ),
  conflicting_target_state_status: copy(
    ["State и status Target не совпадают", "Target state and status disagree"],
    [
      "Состояние Target противоречит его бинарному результату.",
      "The Target state contradicts its binary result.",
    ],
    `${TARGET_STATE} / ${TARGET_STATUS}`,
    [
      "Публикуйте согласованные значения Target из одного запуска.",
      "Publish consistent Target values from the same run.",
    ],
  ),
  invalid_target_duration: copy(
    ["Duration Target некорректна", "Target duration is invalid"],
    [
      "Продолжительность Target отрицательная либо не является конечным числом.",
      "The Target duration is negative or not finite.",
    ],
    DURATION,
    [
      "Публикуйте duration Target в неотрицательных секундах.",
      "Publish Target duration as non-negative seconds.",
    ],
  ),
  conflicting_target_duration: copy(
    ["Duration Target не совпадает", "Target durations conflict"],
    [
      "Для одного target_id получено несколько значений duration.",
      "Multiple duration values were returned for one target_id.",
    ],
    DURATION,
    [
      "Уберите дубли Target duration или выровняйте значения.",
      "Remove duplicate Target-duration series or make their values consistent.",
    ],
  ),
  invalid_target_ttfb: copy(
    ["TTFB Target некорректен", "Target TTFB is invalid"],
    [
      "TTFB Target отрицателен либо не является конечным числом.",
      "The Target TTFB is negative or not finite.",
    ],
    TTFB,
    [
      "Публикуйте TTFB Target в неотрицательных секундах.",
      "Publish Target TTFB as non-negative seconds.",
    ],
  ),
  conflicting_target_ttfb: copy(
    ["TTFB Target не совпадает", "Target TTFB values conflict"],
    [
      "Для одного target_id получено несколько значений TTFB.",
      "Multiple TTFB values were returned for one target_id.",
    ],
    TTFB,
    [
      "Уберите дубли Target TTFB или выровняйте значения.",
      "Remove duplicate Target-TTFB series or make their values consistent.",
    ],
  ),
  invalid_assertion_state: copy(
    ["Состояние Assertion некорректно", "Assertion state is invalid"],
    [
      "One-hot серии Assertion не обозначают ровно одно допустимое состояние.",
      "The assertion one-hot series do not identify exactly one allowed state.",
    ],
    ASSERTION_STATE,
    [
      "Оставьте одно активное допустимое состояние для каждого assertion_id.",
      "Leave exactly one allowed active state for each assertion_id.",
    ],
  ),
  conflicting_assertion_state: copy(
    ["Состояния Assertion противоречат друг другу", "Assertion states conflict"],
    [
      "Для одного Assertion получены дубли или несколько активных состояний.",
      "Duplicate or multiple active states were returned for one assertion.",
    ],
    ASSERTION_STATE,
    [
      "Исправьте one-hot публикацию состояния Assertion.",
      "Fix the assertion one-hot state publication.",
    ],
  ),
  conflicting_assertion_state_match: copy(
    ["State и match Assertion не совпадают", "Assertion state and match disagree"],
    [
      "Состояние Assertion противоречит его бинарному результату.",
      "The assertion state contradicts its binary result.",
    ],
    `${ASSERTION_STATE} / ${ASSERTION}`,
    [
      "Публикуйте согласованные значения Assertion из одного запуска.",
      "Publish consistent assertion values from the same run.",
    ],
  ),
  invalid_error_reason: copy(
    ["Категория ошибки отклонена", "Error category was rejected"],
    [
      "Исполнитель передал неизвестную или небезопасную категорию reason.",
      "The runner returned an unknown or unsafe reason category.",
    ],
    ERRORS,
    [
      "Используйте только документированные безопасные категории reason.",
      "Use only documented safe reason categories.",
    ],
  ),
  invalid_error_count: copy(
    ["Счётчик ошибок некорректен", "Error counter is invalid"],
    [
      "Значение счётчика отрицательное, дробное, слишком большое или нечисловое.",
      "The counter is negative, fractional, too large, or non-numeric.",
    ],
    ERRORS,
    [
      "Публикуйте неотрицательный целочисленный накопительный счётчик.",
      "Publish a non-negative integer cumulative counter.",
    ],
  ),
  conflicting_error_count: copy(
    ["Счётчики одной ошибки не совпадают", "Error counters conflict"],
    [
      "Для одной категории reason получены разные значения счётчика.",
      "Conflicting counter values were returned for one reason category.",
    ],
    ERRORS,
    [
      "Уберите дубли серий либо согласуйте labels и значение счётчика.",
      "Remove duplicate series or make their labels and counter values consistent.",
    ],
  ),
  missing_current_result: copy(
    ["Результат исчез из текущего снимка", "Result disappeared from the current snapshot"],
    [
      "Ранее известная комбинация Check больше не публикуется и сохранена как неполная.",
      "A previously known Check combination is no longer published and is retained as incomplete.",
    ],
    `${REQUIRED_STATUS} / ${REQUIRED_TIMESTAMP}`,
    [
      "Проверьте исполнителя и восстановите публикацию либо корректно удалите комбинацию из inventory.",
      "Check the runner and restore publication, or remove the combination from inventory intentionally.",
    ],
  ),
  check_info_unavailable: copy(
    ["Inventory Checks временно недоступен", "Check inventory is temporarily unavailable"],
    [
      "Основные результаты рассчитаны, но необязательный запрос inventory завершился ошибкой.",
      "Primary results were evaluated, but the optional inventory query failed.",
    ],
    INFO,
    [
      "Проверьте метрику inventory; отсутствие этого запроса не означает отказ Check.",
      "Check the inventory metric; this query failure does not mean the Check failed.",
    ],
  ),
  check_state_unavailable: copy(
    ["Состояние исполнителя временно недоступно", "Executor state is temporarily unavailable"],
    [
      "Основной статус рассчитан, но необязательный запрос подробного state завершился ошибкой.",
      "The primary status was evaluated, but the optional detailed-state query failed.",
    ],
    STATE,
    [
      "Проверьте метрику state; используйте основной статус как актуальный итог.",
      "Check the state metric and use the primary status as the current outcome.",
    ],
  ),
  check_canary_unavailable: copy(
    ["Canary-метрика временно недоступна", "The canary metric is temporarily unavailable"],
    [
      "Основной статус рассчитан, но необязательные canary-результаты не получены.",
      "The primary status was evaluated, but optional canary results were unavailable.",
    ],
    CANARY,
    [
      "Проверьте canary-метрику; её отсутствие само по себе не меняет статус Check.",
      "Check the canary metric; its absence alone does not change Check status.",
    ],
  ),
  check_targets_unavailable: copy(
    ["Результаты Targets временно недоступны", "Target results are temporarily unavailable"],
    [
      "Основной статус рассчитан, но необязательные бинарные результаты Targets не получены.",
      "The primary status was evaluated, but optional binary Target results were unavailable.",
    ],
    TARGET_STATUS,
    [
      "Проверьте Target-метрику; отсутствие детализации не означает отказ Check.",
      "Check the Target metric; missing detail does not mean the Check failed.",
    ],
  ),
  check_target_states_unavailable: copy(
    ["Состояния Targets временно недоступны", "Target states are temporarily unavailable"],
    [
      "Основной статус рассчитан, но необязательные подробные состояния Targets не получены.",
      "The primary status was evaluated, but optional detailed Target states were unavailable.",
    ],
    TARGET_STATE,
    [
      "Проверьте метрику состояния Targets; не подменяйте ею основной статус.",
      "Check the Target-state metric; do not substitute it for the primary status.",
    ],
  ),
  check_duration_unavailable: copy(
    ["Метрика duration временно недоступна", "The duration metric is temporarily unavailable"],
    [
      "Основной статус рассчитан, но необязательный запрос продолжительности завершился ошибкой.",
      "The primary status was evaluated, but the optional duration query failed.",
    ],
    DURATION,
    [
      "Проверьте метрику duration; отсутствие latency не означает отказ Check.",
      "Check the duration metric; missing latency does not mean the Check failed.",
    ],
  ),
  check_ttfb_unavailable: copy(
    ["Метрика TTFB временно недоступна", "The TTFB metric is temporarily unavailable"],
    [
      "Основной статус рассчитан, но необязательный запрос TTFB завершился ошибкой.",
      "The primary status was evaluated, but the optional TTFB query failed.",
    ],
    TTFB,
    [
      "Проверьте доступность метрики и правила запроса в Prometheus; статус Check менять не требуется.",
      "Check the metric and Prometheus query; no Check status change is required.",
    ],
  ),
  check_assertion_states_unavailable: copy(
    ["Состояния Assertions временно недоступны", "Assertion states are temporarily unavailable"],
    [
      "Основной статус рассчитан, но необязательные подробные состояния Assertions не получены.",
      "The primary status was evaluated, but optional detailed assertion states were unavailable.",
    ],
    ASSERTION_STATE,
    [
      "Проверьте метрику состояний Assertions; основной статус остаётся источником итога.",
      "Check the assertion-state metric; the primary status remains the outcome source.",
    ],
  ),
  check_assertions_unavailable: copy(
    ["Результаты Assertions временно недоступны", "Assertion results are temporarily unavailable"],
    [
      "Основной статус рассчитан, но необязательные бинарные результаты Assertions не получены.",
      "The primary status was evaluated, but optional binary assertion results were unavailable.",
    ],
    ASSERTION,
    [
      "Проверьте assertion-метрику; отсутствие детализации не означает отказ Check.",
      "Check the assertion metric; missing detail does not mean the Check failed.",
    ],
  ),
  check_error_reasons_unavailable: copy(
    ["Счётчики ошибок временно недоступны", "Error counters are temporarily unavailable"],
    [
      "Основной статус рассчитан, но необязательные накопительные счётчики категорий ошибок не получены.",
      "The primary status was evaluated, but optional cumulative error-category counters were unavailable.",
    ],
    ERRORS,
    [
      "Проверьте метрику счётчиков; её отсутствие не описывает текущую причину результата.",
      "Check the counter metric; its absence does not describe the current result reason.",
    ],
  ),
  related_alerts_truncated: copy(
    ["Список связанных алертов сокращён", "The related-alert list is truncated"],
    [
      "Alert Hub вернул только безопасно ограниченную часть связанных алертов.",
      "Alert Hub returned only the bounded portion of related alerts.",
    ],
    "Alert Hub incident index",
    [
      "Откройте список инцидентов для полного поиска по check_id.",
      "Open the incident list for a complete search by check_id.",
    ],
  ),
  related_incidents_truncated: copy(
    ["Список связанных инцидентов сокращён", "The related-incident list is truncated"],
    [
      "Alert Hub вернул только безопасно ограниченную часть связанных инцидентов.",
      "Alert Hub returned only the bounded portion of related incidents.",
    ],
    "Alert Hub incident index",
    [
      "Откройте список инцидентов для полного поиска по check_id.",
      "Open the incident list for a complete search by check_id.",
    ],
  ),
  incident_relations_unavailable: copy(
    ["Связи с инцидентами недоступны", "Incident relationships are unavailable"],
    [
      "Текущий ответ не подтвердил связи Check с локальными инцидентами.",
      "The current response could not confirm this Check's local incident relationships.",
    ],
    "Alert Hub incident index",
    [
      "Повторите запрос; если ошибка сохраняется, проверьте локальную базу и журнал API.",
      "Retry; if it persists, inspect the local database and API logs.",
    ],
  ),
};

const SAFE_CODE = /^[a-z][a-z0-9_]{0,63}$/;

const EXECUTOR_STATES: Record<string, Localized> = {
  success: ["Успешно", "Success"],
  failure: ["Ошибка проверки", "Failure"],
  error: ["Ошибка выполнения", "Execution error"],
  stale: ["Устарело", "Stale"],
  disabled: ["Отключено", "Disabled"],
  unknown: ["Неизвестно", "Unknown"],
  match: ["Совпадает", "Match"],
  mismatch: ["Не совпадает", "Mismatch"],
};

const ERROR_REASONS: Record<string, readonly [label: Localized, detail: Localized]> = {
  connect: [
    ["Подключение", "Connection"],
    [
      "Не удалось установить соединение с Target.",
      "A connection to the Target could not be established.",
    ],
  ],
  proxy: [
    ["Прокси", "Proxy"],
    ["Запрос завершился ошибкой на этапе прокси.", "The request failed while using the proxy."],
  ],
  dns: [
    ["DNS", "DNS"],
    [
      "Имя Target не удалось разрешить через DNS.",
      "The Target name could not be resolved through DNS.",
    ],
  ],
  timeout: [
    ["Тайм-аут", "Timeout"],
    [
      "Операция не завершилась в отведённое время.",
      "The operation did not finish within its timeout.",
    ],
  ],
  tls: [
    ["TLS", "TLS"],
    [
      "Защищённое соединение не прошло проверку или согласование.",
      "The secure connection failed validation or negotiation.",
    ],
  ],
  http_status: [
    ["HTTP-статус", "HTTP status"],
    ["Target вернул неожидаемый HTTP-статус.", "The Target returned an unexpected HTTP status."],
  ],
  body_mismatch: [
    ["Содержимое ответа", "Response body"],
    [
      "Тело ответа не соответствует ожидаемому шаблону.",
      "The response body did not match the expected pattern.",
    ],
  ],
  egress_mismatch: [
    ["Исходящий адрес", "Egress identity"],
    [
      "Фактический egress не совпал с ожидаемым.",
      "The observed egress identity did not match the expected value.",
    ],
  ],
  response_invalid: [
    ["Некорректный ответ", "Invalid response"],
    [
      "Ответ Target нельзя корректно разобрать или проверить.",
      "The Target response could not be parsed or validated.",
    ],
  ],
  config_invalid: [
    ["Конфигурация", "Configuration"],
    [
      "Исполнитель отклонил некорректную конфигурацию проверки.",
      "The runner rejected invalid Check configuration.",
    ],
  ],
  unsupported: [
    ["Не поддерживается", "Unsupported"],
    [
      "Исполнитель не поддерживает запрошенную операцию или режим.",
      "The runner does not support the requested operation or mode.",
    ],
  ],
  runtime_start: [
    ["Запуск runtime", "Runtime start"],
    ["Среда выполнения не смогла запуститься.", "The execution runtime could not start."],
  ],
  runtime_exit: [
    ["Завершение runtime", "Runtime exit"],
    ["Среда выполнения завершилась с ошибкой.", "The execution runtime exited with an error."],
  ],
  scheduler: [
    ["Планировщик", "Scheduler"],
    [
      "Планировщик не смог запустить проверку как ожидалось.",
      "The scheduler could not start the Check as expected.",
    ],
  ],
  source_fetch: [
    ["Получение Source", "Source fetch"],
    ["Исполнитель не смог получить данные Source.", "The runner could not fetch Source data."],
  ],
  source_parse: [
    ["Разбор Source", "Source parsing"],
    [
      "Полученные данные Source не удалось разобрать.",
      "The fetched Source data could not be parsed.",
    ],
  ],
  identity_conflict: [
    ["Конфликт идентичности", "Identity conflict"],
    [
      "Набор идентификаторов результата оказался противоречивым.",
      "The result identity fields were inconsistent.",
    ],
  ],
  internal: [
    ["Внутренняя ошибка", "Internal error"],
    [
      "Исполнитель сообщил внутреннюю ошибку без безопасной детализации.",
      "The runner reported an internal error without safe detail.",
    ],
  ],
};

function localized(language: DiagnosticLanguage, value: Localized): string {
  return language === "ru" ? value[0] : value[1];
}

export function describeCheckDiagnostic(
  rawCode: string,
  language: DiagnosticLanguage,
): CheckDiagnostic {
  const normalized = rawCode.trim();
  const safeCode = SAFE_CODE.test(normalized) ? normalized : "unknown_diagnostic";
  const known = DIAGNOSTICS[safeCode];
  if (known) {
    return {
      code: safeCode,
      title: localized(language, known.title),
      detail: localized(language, known.detail),
      metric: known.metric,
      action: localized(language, known.action),
      known: true,
    };
  }
  return {
    code: safeCode,
    title: localized(language, ["Неизвестный диагностический сигнал", "Unknown diagnostic signal"]),
    detail: localized(language, [
      "Alert Hub вернул код, который эта версия интерфейса пока не распознаёт; вывод о состоянии не подменяется.",
      "Alert Hub returned a code this UI version does not recognize; no status conclusion was inferred.",
    ]),
    metric: "—",
    action: localized(language, [
      "Сверьте версии frontend и backend и проверьте журнал backend по этому Check.",
      "Compare frontend and backend versions and inspect backend logs for this Check.",
    ]),
    known: false,
  };
}

export function describeCheckExecutorState(
  rawState: string,
  language: DiagnosticLanguage,
): CheckExecutorStateDescription {
  const normalized = rawState.trim().toLowerCase();
  const safe = SAFE_CODE.test(normalized);
  const known = safe ? EXECUTOR_STATES[normalized] : undefined;
  return {
    state: known ? normalized : "unknown",
    label: localized(
      language,
      known ?? ["Неизвестное состояние исполнителя", "Unknown executor state"],
    ),
    known: Boolean(known),
  };
}

export function describeCheckErrorReason(
  rawReason: string,
  language: DiagnosticLanguage,
): CheckErrorReasonDescription {
  const normalized = rawReason.trim().toLowerCase();
  const safeReason = SAFE_CODE.test(normalized) ? normalized : "unknown_reason";
  const known = ERROR_REASONS[safeReason];
  if (known) {
    return {
      reason: safeReason,
      label: localized(language, known[0]),
      detail: localized(language, known[1]),
      known: true,
    };
  }
  return {
    reason: safeReason,
    label: localized(language, ["Другая причина", "Other reason"]),
    detail: localized(language, [
      "Исполнитель сообщил неизвестную этой версии интерфейса безопасную категорию ошибки.",
      "The runner reported a safe error category this UI version does not recognize.",
    ]),
    known: false,
  };
}
