(function () {
  const UI_STRINGS = {
    en: {
      documentMonitoringTitle: 'DevAI — Vigil Console',
      landingDocTitle: 'DevAI',
      auditDocTitle: 'DevAI — Audit Forge',
      brandTitle: 'DevAI',
      monitoringSubtitle: 'Localized auditing fabric with multilingual insights',
      landingAuditTitle: 'Network Audit',
      landingAuditSubtitle: 'Run adaptive scanning with noise-aware AI remediation workflows',
      landingMonitoringTitle: 'DevAI Console',
      landingMonitoringSubtitle: 'Realtime observability decks with multilingual AI decisions',
      backToLanding: 'Back',
      runAudit: 'Run Audit',
      auditForgeTitle: 'Audit Forge',
      auditHint: 'Safe whitelist ports are ignored by default; only anomalies are listed.',
      anomalousPorts: 'Anomalous Open Ports',
      rawPayload: 'Raw Payload',
      aiRemediation: 'AI Remediation Plan',
      vulnPlaybookHeading: 'Version-aware threat playbooks',
      monitoringSidebarHint: 'Add hosts, poll metrics, inspect dependency-aware AI narration.',
      menuHosts: 'Hosts',
      menuLive: 'Live Dashboard',
      menuAi: 'AI Decisions',
      hostsTitle: 'Hosts',
      liveTitle: 'Live Dashboard',
      aiDecisionsTitle: 'AI Decisions',
      refresh: 'Refresh',
      pollNow: 'Poll Now',
      addHost: 'Add',
      updateHost: 'Update',
      clear: 'Clear',
      deviceServer: 'Server',
      deviceSwitch: 'Switch',
      deviceVm: 'VM',
      deviceType: 'Device Type',
      dateAdded: 'Date Added',
      actions: 'Actions',
      status: 'Status',
      polledAt: 'Polled At',
      ip: 'IP',
      port: 'Port',
      protocol: 'Protocol',
      service: 'Service',
      process: 'Process',
      hostname: 'Hostname',
      cpu: 'CPU %',
      ram: 'RAM %',
      disk: 'Disk %',
      temp: 'Temp C',
      vendorProfileLabel: 'Hardware SNMP profile',
      optgroupDellEmc: 'Dell EMC',
      optgroupDellNetworking: 'Dell Networking',
      optgroupCisco: 'Cisco',
      optgroupHPE: 'HPE',
      optgroupHPEAruba: 'HPE Aruba',
      optgroupArista: 'Arista',
      optgroupJuniper: 'Juniper',
      optgroupFortinet: 'Fortinet',
      optgroupPaloAlto: 'Palo Alto Networks',
      optgroupMikroTik: 'MikroTik',
      optgroupDLink: 'D-Link',
      optgroupUbiquiti: 'Ubiquiti',
      optgroupVMware: 'VMware',
      optgroupNetApp: 'NetApp',
      optgroupSynology: 'Synology',
      optgroupApc: 'APC',
      optgroupGenericOs: 'Generic OS',
      delete: 'Delete',
      edit: 'Edit',
      noData: 'No data',
      subnetPlaceholder: '192.168.1.0/24',
      hostInternalIdPlaceholder: 'Internal id locked while editing',
      hostHostnamePlaceholder: 'Hostname',
      hostIpPlaceholder: 'IPv4 address',
      hostInsightKicker: 'Host telemetry insight',
      closeModal: 'Close',
      metricPickerLabel: 'Metric focus',
      chartStartLabel: 'Start',
      chartEndLabel: 'End',
      loadHistory: 'Load range',
      heatClusterServers: 'Servers',
      heatClusterSwitches: 'Switches',
      heatClusterVms: 'Virtual machines',
      heatClusterWebsites: 'Websites',
      responseTimeMs: 'Response time (ms)',
      httpStatusShort: 'HTTP status',
      statusPaused: 'Paused',
      statusOffline: 'Offline',
      metricNA: 'N/A',
      protocolHttps: 'HTTPS',
      maintenanceModeLabel: 'Maintenance mode (pause checks and alerts)',
      legendIssue: 'Attention',
      logoutLink: 'Sign out',
      pollingIntervalLabel: 'Polling interval',
      pollProtocolLabel: 'Protocol',
      snmpCommunityLabel: 'SNMP COMMUNITY STRING',
      snmpCommunityPlaceholder: 'e.g., public',
      snmpPortLabel: 'SNMP PORT',
      snmpVersionLabel: 'SNMP VERSION',
      snmpVersionV2c: 'v2c',
      snmpVersionV3: 'v3',
      snmpv3UserLabel: 'SNMPv3 username',
      snmpv3AuthAlgoLabel: 'Auth algorithm',
      snmpv3AuthKeyLabel: 'Auth password',
      snmpv3PrivAlgoLabel: 'Privacy algorithm',
      snmpv3PrivKeyLabel: 'Privacy password',
      interval15: '15 seconds',
      interval30: '30 seconds',
      interval60: '60 seconds',
      interval300: '5 minutes',
      protocolSnmp: 'SNMP',
      protocolSsh: 'SSH',
      protocolHttp: 'HTTP',
      addHostModal: 'Add host',
      editHostModal: 'Edit host',
      saveHost: 'Save',
      cancelModal: 'Cancel',
      hostCrudKicker: 'Host configuration',
      documentDashboardTitle: 'DevAI — Command Deck',
      dashboardTagline: 'Unified audit and monitoring',
      navHome: 'Home',
      navAudit: 'Network Audit',
      navMonitoring: 'Monitoring',
      navHosts: 'Host Management',
      navAi: 'AI Decisions',
      navAlerts: 'Alerts & Logs',
      navProfile: 'User Profile',
      navSettings: 'System Settings',
      navHomeTooltip: 'General health and statistics',
      navAuditTooltip: 'Port scanning and whitelist intelligence',
      navMonitoringTooltip: 'Live host grids and graphs',
      navHostsTooltip: 'Add or edit monitored hosts',
      navAiTooltip: 'Predictive advice and manuals',
      navAlertsTooltip: 'Telegram delivery history',
      navProfileTooltip: 'Account, privileges, password',
      navSettingsTooltip: 'Telegram API, themes, language',
      sidebarCollapseTooltip: 'Collapse or expand sidebar',
      homeTitle: 'Home',
      homeCardHosts: 'Registered hosts',
      homeCardOnline: 'Hosts online',
      homeCardMetrics: 'Telemetry streams',
      auditLoadingLabel: 'Surface scan in progress',
      pollLoadingLabel: 'SNMP polling cycle',
      aiAnomalySectionTitle: 'Real-time anomaly alerts',
      aiPredictiveSectionTitle: 'Predictive AI Insights',
      aiManualSectionTitle: 'Manual and playbook intelligence',
      alertsTitle: 'Alerts & Logs',
      alertColTime: 'Time',
      alertColHost: 'Host',
      alertColType: 'Type',
      alertColStatus: 'Delivery',
      alertColMessage: 'Message',
      profileTitle: 'User Profile',
      profileUsernameLabel: 'Username',
      profileRoleLabel: 'Role',
      profilePasswordHeading: 'Change password',
      profileCurrentPassword: 'Current password',
      profileNewPassword: 'New password',
      profileConfirmPassword: 'Confirm new password',
      profilePasswordSubmit: 'Update password',
      profilePasswordOk: 'Password updated',
      profilePasswordMismatch: 'New passwords do not match',
      profilePasswordFail: 'Update failed',
      settingsTitle: 'System Settings',
      settingsAppearance: 'Appearance',
      settingsThemeLabel: 'Theme',
      settingsThemeHint: 'Your theme is stored per user.',
      settingsTelegramHeading: 'Telegram delivery',
      settingsTelegramToken: 'Bot token',
      settingsTelegramChat: 'Chat ID',
      settingsSaveTelegram: 'Save Telegram settings',
      settingsTelegramAdminNote: 'Only administrators can change Telegram credentials.',
      settingsTelegramSaved: 'Telegram settings saved',
      settingsTelegramForbidden: 'Insufficient privileges',
      themeVibrantDark: 'Vibrant Dark',
      themeSlateDark: 'Slate Dark',
      themeLight: 'Light Mode',
      loginDocTitle: 'DevAI — Sign in',
      loginSubtitle: 'Secure observability console',
      loginUsername: 'Username',
      loginPassword: 'Password',
      loginRemember: 'Remember me',
      loginSubmit: 'Sign in',
      loginErrorInvalid: 'Invalid credentials',
      manualScoreLabel: 'Relevance',
      navTopology: 'Network Topology',
      navTopologyTooltip: 'Interactive dependency graph',
      topologyTitle: 'Network Topology',
      discoveryOpen: 'Auto-Discovery',
      discoveryKicker: 'Subnet sweep',
      discoveryTitle: 'Auto-Discovery',
      discoveryCidrLabel: 'Target CIDR',
      discoveryCidrPlaceholder: '192.168.1.0/24',
      discoveryRun: 'Scan subnet',
      discoveryImport: 'Import selected',
      discoveryLoadingLabel: 'Discovering active hosts',
      discoveryNoSelection: 'Select at least one address',
      discoveryForbidden: 'Administrator role required',
      deploySsh: 'Deploy Fix (SSH)',
      sshUsernameLabel: 'SSH username',
      sshPasswordLabel: 'SSH password',
      sshPasswordPlaceholder: 'Leave blank to keep existing password',
      sshPortLabel: 'SSH port',
      deviceWebsite: 'Website',
      slaUptimeLabel: 'SLA uptime',
      auditTrailTitle: 'Compliance audit trail',
      auditColTime: 'Time',
      auditColUser: 'User',
      auditColAction: 'Action',
      toastSshOk: 'Remediation command completed',
      toastSshFail: 'SSH execution failed',
    },
    ru: {
      documentMonitoringTitle: 'DevAI — консоль наблюдения',
      landingDocTitle: 'DevAI',
      auditDocTitle: 'DevAI — кузница аудита',
      brandTitle: 'DevAI',
      monitoringSubtitle: 'Локализованная аудиторская ткань с многоязычным интеллектом',
      landingAuditTitle: 'Сетевой аудит',
      landingAuditSubtitle: 'Адаптивное сканирование с ИИ-устранением и подавлением шума',
      landingMonitoringTitle: 'Консоль DevAI',
      landingMonitoringSubtitle: 'Наблюдаемость в реальном времени с многоязычными решениями ИИ',
      backToLanding: 'Назад',
      runAudit: 'Запустить аудит',
      auditForgeTitle: 'Кузница аудита',
      auditHint: 'Безопасные порты из белого списка скрываются; отображаются только аномалии.',
      anomalousPorts: 'Аномальные открытые порты',
      rawPayload: 'Сырой ответ',
      aiRemediation: 'План ИИ-устранения',
      vulnPlaybookHeading: 'Плейбуки угроз по версиям сервисов',
      monitoringSidebarHint: 'Добавьте хосты, опросите метрики, изучите ИИ с учетом зависимостей.',
      menuHosts: 'Хосты',
      menuLive: 'Живой дашборд',
      menuAi: 'Решения ИИ',
      hostsTitle: 'Хосты',
      liveTitle: 'Живой дашборд',
      aiDecisionsTitle: 'Решения ИИ',
      refresh: 'Обновить',
      pollNow: 'Опросить',
      addHost: 'Добавить',
      updateHost: 'Обновить',
      clear: 'Очистить',
      deviceServer: 'Сервер',
      deviceSwitch: 'Коммутатор',
      deviceVm: 'ВМ',
      deviceType: 'Тип устройства',
      dateAdded: 'Добавлено',
      actions: 'Действия',
      status: 'Статус',
      polledAt: 'Время опроса',
      ip: 'IP',
      port: 'Порт',
      protocol: 'Протокол',
      service: 'Сервис',
      process: 'Процесс',
      hostname: 'Имя хоста',
      cpu: 'CPU %',
      ram: 'RAM %',
      disk: 'Disk %',
      temp: 'Темп C',
      vendorProfileLabel: 'Профиль SNMP оборудования',
      optgroupDellEmc: 'Dell EMC',
      optgroupDellNetworking: 'Dell Networking',
      optgroupCisco: 'Cisco',
      optgroupHPE: 'HPE',
      optgroupHPEAruba: 'HPE Aruba',
      optgroupArista: 'Arista',
      optgroupJuniper: 'Juniper',
      optgroupFortinet: 'Fortinet',
      optgroupPaloAlto: 'Palo Alto Networks',
      optgroupMikroTik: 'MikroTik',
      optgroupDLink: 'D-Link',
      optgroupUbiquiti: 'Ubiquiti',
      optgroupVMware: 'VMware',
      optgroupNetApp: 'NetApp',
      optgroupSynology: 'Synology',
      optgroupApc: 'APC',
      optgroupGenericOs: 'Универсальные ОС',
      delete: 'Удалить',
      edit: 'Редактировать',
      noData: 'Нет данных',
      subnetPlaceholder: '192.168.1.0/24',
      hostInternalIdPlaceholder: 'Внутренний id заблокирован при редактировании',
      hostHostnamePlaceholder: 'Имя хоста',
      hostIpPlaceholder: 'Адрес IPv4',
      hostInsightKicker: 'Инсайт телеметрии',
      closeModal: 'Закрыть',
      metricPickerLabel: 'Метрика',
      chartStartLabel: 'Начало',
      chartEndLabel: 'Конец',
      loadHistory: 'Загрузить',
      heatClusterServers: 'Серверы',
      heatClusterSwitches: 'Коммутаторы',
      heatClusterVms: 'Виртуальные машины',
      heatClusterWebsites: 'Веб-сайты',
      responseTimeMs: 'Время ответа (мс)',
      httpStatusShort: 'HTTP статус',
      statusPaused: 'Пауза',
      statusOffline: 'Не в сети',
      metricNA: 'Н/Д',
      protocolHttps: 'HTTPS',
      maintenanceModeLabel: 'Режим обслуживания (пауза проверок и оповещений)',
      legendIssue: 'Внимание',
      logoutLink: 'Выход',
      pollingIntervalLabel: 'Интервал опроса',
      pollProtocolLabel: 'Протокол',
      snmpCommunityLabel: 'СТРОКА SNMP COMMUNITY',
      snmpCommunityPlaceholder: 'например, public',
      snmpPortLabel: 'ПОРТ SNMP',
      snmpVersionLabel: 'ВЕРСИЯ SNMP',
      snmpVersionV2c: 'v2c',
      snmpVersionV3: 'v3',
      snmpv3UserLabel: 'Имя пользователя SNMPv3',
      snmpv3AuthAlgoLabel: 'Алгоритм аутентификации',
      snmpv3AuthKeyLabel: 'Пароль аутентификации',
      snmpv3PrivAlgoLabel: 'Алгоритм шифрования',
      snmpv3PrivKeyLabel: 'Пароль шифрования',
      interval15: '15 секунд',
      interval30: '30 секунд',
      interval60: '60 секунд',
      interval300: '5 минут',
      protocolSnmp: 'SNMP',
      protocolSsh: 'SSH',
      protocolHttp: 'HTTP',
      addHostModal: 'Добавить хост',
      editHostModal: 'Изменить хост',
      saveHost: 'Сохранить',
      cancelModal: 'Отмена',
      hostCrudKicker: 'Конфигурация хоста',
      documentDashboardTitle: 'DevAI — командная палуба',
      dashboardTagline: 'Единый аудит и мониторинг',
      navHome: 'Главная',
      navAudit: 'Сетевой аудит',
      navMonitoring: 'Мониторинг',
      navHosts: 'Управление хостами',
      navAi: 'Решения ИИ',
      navAlerts: 'Оповещения и журналы',
      navProfile: 'Профиль',
      navSettings: 'Системные настройки',
      navHomeTooltip: 'Общее состояние и статистика',
      navAuditTooltip: 'Сканирование портов и белые списки',
      navMonitoringTooltip: 'Живые сетки и графики',
      navHostsTooltip: 'Добавление и правка хостов',
      navAiTooltip: 'Прогнозы и руководства',
      navAlertsTooltip: 'История Telegram',
      navProfileTooltip: 'Учетная запись и пароль',
      navSettingsTooltip: 'Telegram, темы, язык',
      sidebarCollapseTooltip: 'Свернуть или развернуть панель',
      homeTitle: 'Главная',
      homeCardHosts: 'Зарегистрированные хосты',
      homeCardOnline: 'Хосты онлайн',
      homeCardMetrics: 'Потоки телеметрии',
      auditLoadingLabel: 'Сканирование поверхности',
      pollLoadingLabel: 'Цикл опроса SNMP',
      aiAnomalySectionTitle: 'Аномалии в реальном времени',
      aiPredictiveSectionTitle: 'Прогнозные AI Insights',
      aiManualSectionTitle: 'Руководства и плейбуки',
      alertsTitle: 'Оповещения и журналы',
      alertColTime: 'Время',
      alertColHost: 'Хост',
      alertColType: 'Тип',
      alertColStatus: 'Доставка',
      alertColMessage: 'Сообщение',
      profileTitle: 'Профиль',
      profileUsernameLabel: 'Имя пользователя',
      profileRoleLabel: 'Роль',
      profilePasswordHeading: 'Смена пароля',
      profileCurrentPassword: 'Текущий пароль',
      profileNewPassword: 'Новый пароль',
      profileConfirmPassword: 'Подтверждение пароля',
      profilePasswordSubmit: 'Обновить пароль',
      profilePasswordOk: 'Пароль обновлен',
      profilePasswordMismatch: 'Пароли не совпадают',
      profilePasswordFail: 'Ошибка обновления',
      settingsTitle: 'Системные настройки',
      settingsAppearance: 'Оформление',
      settingsThemeLabel: 'Тема',
      settingsThemeHint: 'Тема сохраняется для пользователя.',
      settingsTelegramHeading: 'Доставка Telegram',
      settingsTelegramToken: 'Токен бота',
      settingsTelegramChat: 'Chat ID',
      settingsSaveTelegram: 'Сохранить Telegram',
      settingsTelegramAdminNote: 'Только администраторы меняют учетные данные Telegram.',
      settingsTelegramSaved: 'Настройки Telegram сохранены',
      settingsTelegramForbidden: 'Недостаточно прав',
      themeVibrantDark: 'Насыщенная тьма',
      themeSlateDark: 'Сланцевая тьма',
      themeLight: 'Светлая тема',
      loginDocTitle: 'DevAI — вход',
      loginSubtitle: 'Защищенная консоль наблюдения',
      loginUsername: 'Имя пользователя',
      loginPassword: 'Пароль',
      loginRemember: 'Запомнить меня',
      loginSubmit: 'Войти',
      loginErrorInvalid: 'Неверные учетные данные',
      manualScoreLabel: 'Релевантность',
      navTopology: 'Топология сети',
      navTopologyTooltip: 'Интерактивный граф зависимостей',
      topologyTitle: 'Топология сети',
      discoveryOpen: 'Автообнаружение',
      discoveryKicker: 'Скан подсети',
      discoveryTitle: 'Автообнаружение',
      discoveryCidrLabel: 'CIDR',
      discoveryCidrPlaceholder: '192.168.1.0/24',
      discoveryRun: 'Сканировать',
      discoveryImport: 'Импорт выбранных',
      discoveryLoadingLabel: 'Поиск активных узлов',
      discoveryNoSelection: 'Выберите хотя бы один адрес',
      discoveryForbidden: 'Требуется роль администратора',
      deploySsh: 'Применить (SSH)',
      sshUsernameLabel: 'SSH пользователь',
      sshPasswordLabel: 'SSH пароль',
      sshPasswordPlaceholder: 'Пусто — сохранить текущий пароль',
      sshPortLabel: 'SSH порт',
      deviceWebsite: 'Веб-сайт',
      slaUptimeLabel: 'SLA доступность',
      auditTrailTitle: 'Журнал действий',
      auditColTime: 'Время',
      auditColUser: 'Пользователь',
      auditColAction: 'Действие',
      toastSshOk: 'Команда выполнена',
      toastSshFail: 'Ошибка SSH',
    },
    hy: {
      documentMonitoringTitle: 'DevAI — դիտարկման կոնսոլ',
      landingDocTitle: 'DevAI',
      auditDocTitle: 'DevAI — աուդիտի կայան',
      brandTitle: 'DevAI',
      monitoringSubtitle: 'Տեղայնացված աուդիտի հարթակ բազմալեզու վերլուծությամբ',
      landingAuditTitle: 'Ցանցային աուդիտ',
      landingAuditSubtitle: 'Ճկուն սկանավորում՝ աղմուկի նվազեցմամբ և AI վերականգնմամբ',
      landingMonitoringTitle: 'DevAI կոնսոլ',
      landingMonitoringSubtitle: 'Իրական ժամանակի դիտարկում բազմալեզու AI որոշումներով',
      backToLanding: 'Հետ',
      runAudit: 'Գործարկել աուդիտ',
      auditForgeTitle: 'Աուդիտի կայան',
      auditHint: 'Անվտանգ պորտերը թաքցվում են լռելյայն, ցուցադրվում են միայն անոմալիաները։',
      anomalousPorts: 'Անոմալ բաց պորտեր',
      rawPayload: 'Հում պատասխան',
      aiRemediation: 'AI վերականգնման պլան',
      vulnPlaybookHeading: 'Տարբերակային սպառնալիքների պլեյբուքեր',
      monitoringSidebarHint: 'Ավելացրեք հոսթեր, հարցեք մետրիկները, ուսումնասիրեք կախվածություններով AI-ը։',
      menuHosts: 'Հոսթեր',
      menuLive: 'Կենդանի վահանակ',
      menuAi: 'AI որոշումներ',
      hostsTitle: 'Հոսթեր',
      liveTitle: 'Կենդանի վահանակ',
      aiDecisionsTitle: 'AI որոշումներ',
      refresh: 'Թարմացնել',
      pollNow: 'Հարցում',
      addHost: 'Ավելացնել',
      updateHost: 'Թարմացնել',
      clear: 'Մաքրել',
      deviceServer: 'Սերվեր',
      deviceSwitch: 'Սվիչ',
      deviceVm: 'VM',
      deviceType: 'Սարքի տեսակ',
      dateAdded: 'Ավելացված է',
      actions: 'Գործողություններ',
      status: 'Կարգավիճակ',
      polledAt: 'Հարցման ժամ',
      ip: 'IP',
      port: 'Պորտ',
      protocol: 'Պրոտոկոլ',
      service: 'Ծառայություն',
      process: 'Գործընթաց',
      hostname: 'Հոսթի անուն',
      cpu: 'CPU %',
      ram: 'RAM %',
      disk: 'Disk %',
      temp: 'Ջերմ C',
      vendorProfileLabel: 'SNMP ապարատային պրոֆիլ',
      optgroupDellEmc: 'Dell EMC',
      optgroupDellNetworking: 'Dell Networking',
      optgroupCisco: 'Cisco',
      optgroupHPE: 'HPE',
      optgroupHPEAruba: 'HPE Aruba',
      optgroupArista: 'Arista',
      optgroupJuniper: 'Juniper',
      optgroupFortinet: 'Fortinet',
      optgroupPaloAlto: 'Palo Alto Networks',
      optgroupMikroTik: 'MikroTik',
      optgroupDLink: 'D-Link',
      optgroupUbiquiti: 'Ubiquiti',
      optgroupVMware: 'VMware',
      optgroupNetApp: 'NetApp',
      optgroupSynology: 'Synology',
      optgroupApc: 'APC',
      optgroupGenericOs: 'Ընդհանուր ՕՀ',
      delete: 'Ջնջել',
      edit: 'Խմբագրել',
      noData: 'Տվյալներ չկան',
      subnetPlaceholder: '192.168.1.0/24',
      hostInternalIdPlaceholder: 'Ներքին id-ն կողպված է խմբագրման ժամանակ',
      hostHostnamePlaceholder: 'Հոսթի անուն',
      hostIpPlaceholder: 'IPv4 հասցե',
      hostInsightKicker: 'Հոսթի հեռաչափ',
      closeModal: 'Փակել',
      metricPickerLabel: 'Մետրիկա',
      chartStartLabel: 'Սկիզբ',
      chartEndLabel: 'Ավարտ',
      loadHistory: 'Վերագնալ',
      heatClusterServers: 'Սերվերներ',
      heatClusterSwitches: 'Սվիչներ',
      heatClusterVms: 'Վիրտուալ մեքենաներ',
      heatClusterWebsites: 'Կայքեր',
      responseTimeMs: 'Պատասխանի ժամանակ (մս)',
      httpStatusShort: 'HTTP կարգավիճակ',
      statusPaused: 'Դադար',
      statusOffline: 'Անջատված',
      metricNA: 'Ա/Վ',
      protocolHttps: 'HTTPS',
      maintenanceModeLabel: 'Սպասարկման ռեժիմ (դադարեցնել ստուգումները և զգուշացումները)',
      legendIssue: 'Ուշադրություն',
      logoutLink: 'Ելք',
      pollingIntervalLabel: 'Հարցման միջակայք',
      pollProtocolLabel: 'Պրոտոկոլ',
      snmpCommunityLabel: 'SNMP COMMUNITY ՏԵՔՍՏ',
      snmpCommunityPlaceholder: 'օր․ public',
      snmpPortLabel: 'SNMP ՊՈՐՏ',
      snmpVersionLabel: 'SNMP ՏԱՐԲԵՐԱԿ',
      snmpVersionV2c: 'v2c',
      snmpVersionV3: 'v3',
      snmpv3UserLabel: 'SNMPv3 օգտանուն',
      snmpv3AuthAlgoLabel: 'Ավտենտիֆիկացիայի ալգորիթմ',
      snmpv3AuthKeyLabel: 'Ավտենտիֆիկացիայի գաղտնաբառ',
      snmpv3PrivAlgoLabel: 'Գաղտնագրության ալգորիթմ',
      snmpv3PrivKeyLabel: 'Գաղտնագրության գաղտնաբառ',
      interval15: '15 վայրկյան',
      interval30: '30 վայրկյան',
      interval60: '60 վայրկյան',
      interval300: '5 րոպե',
      protocolSnmp: 'SNMP',
      protocolSsh: 'SSH',
      protocolHttp: 'HTTP',
      addHostModal: 'Ավելացնել հոսթ',
      editHostModal: 'Խմբագրել հոսթ',
      saveHost: 'Պահպանել',
      cancelModal: 'Չեղարկել',
      hostCrudKicker: 'Հոսթի կոնֆիգուրացիա',
      documentDashboardTitle: 'DevAI — հրամանական կամուրջ',
      dashboardTagline: 'Միասնական աուդիտ և մոնիտորինգ',
      navHome: 'Գլխավոր',
      navAudit: 'Ցանցային աուդիտ',
      navMonitoring: 'Մոնիտորինգ',
      navHosts: 'Հոսթերի կառավարում',
      navAi: 'AI որոշումներ',
      navAlerts: 'Զգուշացումներ և մատյաններ',
      navProfile: 'Պրոֆիլ',
      navSettings: 'Համակարգի կարգավորումներ',
      navHomeTooltip: 'Ընդհանուր առողջություն և վիճակագրություն',
      navAuditTooltip: 'Պորտերի սկանավորում և whitelist',
      navMonitoringTooltip: 'Կենդանի ցանցեր և գրաֆիկներ',
      navHostsTooltip: 'Հոսթերի ավելացում և խմբագրում',
      navAiTooltip: 'Կանխատեսումներ և ձեռնարկներ',
      navAlertsTooltip: 'Telegram պատմություն',
      navProfileTooltip: 'Հաշիվ, իրավունքներ, գաղտնաբառ',
      navSettingsTooltip: 'Telegram API, թեմաներ, լեզու',
      sidebarCollapseTooltip: 'Կոծկել կամ բացել կողային վահանակը',
      homeTitle: 'Գլխավոր',
      homeCardHosts: 'Գրանցված հոսթեր',
      homeCardOnline: 'Առցանց հոսթեր',
      homeCardMetrics: 'Հեռաչափի հոսքեր',
      auditLoadingLabel: 'Մակերեսի սկանավորում',
      pollLoadingLabel: 'SNMP հարցման ցիկլ',
      aiAnomalySectionTitle: 'Անոմալիաներ իրական ժամանակում',
      aiPredictiveSectionTitle: 'Կանխատեսվող AI Insights',
      aiManualSectionTitle: 'Ձեռնարկներ և պլեյբուքեր',
      alertsTitle: 'Զգուշացումներ և մատյաններ',
      alertColTime: 'Ժամանակ',
      alertColHost: 'Հոսթ',
      alertColType: 'Տեսակ',
      alertColStatus: 'Առաքում',
      alertColMessage: 'Հաղորդագրություն',
      profileTitle: 'Օգտվողի պրոֆիլ',
      profileUsernameLabel: 'Օգտանուն',
      profileRoleLabel: 'Դեր',
      profilePasswordHeading: 'Փոխել գաղտնաբառը',
      profileCurrentPassword: 'Ընթացիկ գաղտնաբառ',
      profileNewPassword: 'Նոր գաղտնաբառ',
      profileConfirmPassword: 'Հաստատել գաղտնաբառը',
      profilePasswordSubmit: 'Թարմացնել գաղտնաբառը',
      profilePasswordOk: 'Գաղտնաբառը թարմացվեց',
      profilePasswordMismatch: 'Գաղտնաբառերը չեն համընկնում',
      profilePasswordFail: 'Թարմացումը ձախողվեց',
      settingsTitle: 'Համակարգի կարգավորումներ',
      settingsAppearance: 'Տեսք',
      settingsThemeLabel: 'Թեմա',
      settingsThemeHint: 'Թեման պահվում է յուրաքանչյուր օգտվողի համար։',
      settingsTelegramHeading: 'Telegram առաքում',
      settingsTelegramToken: 'Բոթի թոքեն',
      settingsTelegramChat: 'Chat ID',
      settingsSaveTelegram: 'Պահպանել Telegram',
      settingsTelegramAdminNote: 'Միայն ադմինիստրատորները կարող են փոխել Telegram տվյալները։',
      settingsTelegramSaved: 'Telegram կարգավորումները պահպանվեցին',
      settingsTelegramForbidden: 'Իրավունքները բավարար չեն',
      themeVibrantDark: 'Վառ մուգ',
      themeSlateDark: 'Պրոֆեսիոնալ մուգ',
      themeLight: 'Լուսավոր ռեժիմ',
      loginDocTitle: 'DevAI — մուտք',
      loginSubtitle: 'Ապահով դիտարկման կոնսոլ',
      loginUsername: 'Օգտանուն',
      loginPassword: 'Գաղտնաբառ',
      loginRemember: 'Հիշել ինձ',
      loginSubmit: 'Մուտք',
      loginErrorInvalid: 'Սխալ տվյալներ',
      manualScoreLabel: 'Համապատասխանություն',
      navTopology: 'Ցանցի տոպոլոգիա',
      navTopologyTooltip: 'Ինտերակտիվ կախվածության գրաֆ',
      topologyTitle: 'Ցանցի տոպոլոգիա',
      discoveryOpen: 'Ավտոբացում',
      discoveryKicker: 'Ենթացանցի սկան',
      discoveryTitle: 'Ավտոբացում',
      discoveryCidrLabel: 'CIDR',
      discoveryCidrPlaceholder: '192.168.1.0/24',
      discoveryRun: 'Սկանավորել',
      discoveryImport: 'Ներմուծել ընտրվածները',
      discoveryLoadingLabel: 'Ակտիվ հանգույցների որոնում',
      discoveryNoSelection: 'Ընտրեք առնվազն մեկ հասցե',
      discoveryForbidden: 'Պահանջվում է ադմինիստրատոր',
      deploySsh: 'Կիրառել (SSH)',
      sshUsernameLabel: 'SSH օգտանուն',
      sshPasswordLabel: 'SSH գաղտնաբառ',
      sshPasswordPlaceholder: 'Դատարկ՝ պահել գործող գաղտնաբառը',
      sshPortLabel: 'SSH պորտ',
      deviceWebsite: 'Կայք',
      slaUptimeLabel: 'SLA հասանելիություն',
      auditTrailTitle: 'Համապատասխանության մատյան',
      auditColTime: 'Ժամանակ',
      auditColUser: 'Օգտվող',
      auditColAction: 'Գործողություն',
      toastSshOk: 'Հրամանը կատարվեց',
      toastSshFail: 'SSH սխալ',
    },
  };

  const STORAGE_KEY = 'audit_ui_lang';
  let currentLanguage = 'en';

  const languageSelect = document.getElementById('language-select');
  const pageName = document.body ? document.body.getAttribute('data-page') : '';

  window.__monitoringRefreshLanguages = window.__monitoringRefreshLanguages || null;
  window.__devaiRole = '';
  window.__devaiHosts = [];

  function vendorSignatureHitsHosts(signature, hosts) {
    var hostList = Array.isArray(hosts) ? hosts : [];
    if (!hostList.length) {
      return false;
    }
    var sig = String(signature || '').trim().toLowerCase();
    if (!sig) {
      return false;
    }
    var tokens = sig.split(/\s+/).filter(Boolean);
    return hostList.some(function (hostRow) {
      var blob = (
        String(hostRow.vendor_template || '') +
        ' ' +
        String(hostRow.device_type || '') +
        ' ' +
        String(hostRow.hostname || '') +
        ' ' +
        String(hostRow.ip_address || '')
      ).toLowerCase();
      return tokens.some(function (token) {
        return blob.indexOf(token) >= 0;
      });
    });
  }

  function filterPlaybooksForHosts(items, hosts, signatureField) {
    var hostList = Array.isArray(hosts) ? hosts : [];
    if (!hostList.length) {
      return [];
    }
    var source = Array.isArray(items) ? items : [];
    return source.filter(function (item) {
      var signatureValue = item[signatureField];
      if (signatureField === 'title') {
        signatureValue = (item.title || '') + ' ' + (item.source_key || '');
      }
      return vendorSignatureHitsHosts(signatureValue, hostList);
    });
  }

  function syncAuditPlaybookPanel(showPanel) {
    var auditPanel = document.getElementById('audit-vuln-playbook-panel');
    var hosts = window.__devaiHosts || [];
    if (!auditPanel) {
      return;
    }
    if (hosts.length > 0 && showPanel) {
      auditPanel.classList.remove('devai-playbook-hidden');
    } else {
      auditPanel.classList.add('devai-playbook-hidden');
    }
  }

  function syncManualPlaybookPanel(showPanel) {
    var manualWrap = document.getElementById('ai-manual-section-wrap');
    var hosts = window.__devaiHosts || [];
    if (!manualWrap) {
      return;
    }
    if (hosts.length > 0 && showPanel) {
      manualWrap.classList.remove('devai-playbook-hidden');
    } else {
      manualWrap.classList.add('devai-playbook-hidden');
    }
  }

  function showDevAIToast(messageText, isError) {
    var root = document.getElementById('sentinel-toast-root');
    if (!root) return;
    var el = document.createElement('div');
    el.className = 'sentinel-toast ' + (isError ? 'err' : 'ok');
    el.textContent = String(messageText || '');
    root.appendChild(el);
    setTimeout(function () {
      try {
        root.removeChild(el);
      } catch (eRem) {}
    }, 5200);
  }

  function t(key) {
    const pack = UI_STRINGS[currentLanguage] || UI_STRINGS.en;
    return Object.prototype.hasOwnProperty.call(pack, key) ? pack[key] : UI_STRINGS.en[key] || key;
  }

  function emphasizeAiTerms(fragment) {
    var escaped = String(fragment || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
    var terms = [
      'DevAI',
      'CRITICAL',
      'CPU',
      'RAM',
      'Disk',
      'Temperature',
      'SNMP',
      'Predictive',
      'Firewall',
      'Timeout',
      'Offline',
      'HTTP',
      'Latency',
      'Memory',
      'Winbox',
      'Nginx',
    ];
    terms.forEach(function (term) {
      var re = new RegExp('\\b(' + term + ')\\b', 'gi');
      escaped = escaped.replace(re, '<strong>$1</strong>');
    });
    return escaped;
  }

  function formatAiNarrative(rawText) {
    var text = String(rawText || '').trim();
    var container = document.createElement('div');
    container.className = 'devai-ai-formatted';
    if (!text) {
      return container;
    }
    var parts = text.split(/\n+|(?<=[.!?])\s+(?=[A-ZDevAI])/).filter(function (p) {
      return String(p || '').trim();
    });
    if (parts.length <= 1) {
      parts = text.split(/\.\s+/).filter(function (p) {
        return String(p || '').trim();
      });
    }
    if (parts.length <= 1) {
      container.innerHTML = emphasizeAiTerms(text);
      return container;
    }
    var list = document.createElement('ul');
    list.className = 'devai-ai-bullet-list';
    parts.forEach(function (part) {
      var li = document.createElement('li');
      li.innerHTML = emphasizeAiTerms(String(part).trim());
      list.appendChild(li);
    });
    container.appendChild(list);
    return container;
  }

  function applyI18nToDom() {
    const htmlLang = currentLanguage === 'hy' ? 'hy' : currentLanguage === 'ru' ? 'ru' : 'en';
    document.documentElement.setAttribute('lang', htmlLang);
    document.querySelectorAll('[data-i18n]').forEach(function (el) {
      const key = el.getAttribute('data-i18n');
      if (!key) return;
      el.textContent = t(key);
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) {
      const key = el.getAttribute('data-i18n-placeholder');
      if (!key) return;
      el.setAttribute('placeholder', t(key));
    });
    document.querySelectorAll('[data-i18n-optgroup]').forEach(function (el) {
      const key = el.getAttribute('data-i18n-optgroup');
      if (!key) return;
      el.label = t(key);
    });
    document.querySelectorAll('[data-i18n-title]').forEach(function (el) {
      const key = el.getAttribute('data-i18n-title');
      if (!key) return;
      el.setAttribute('title', t(key));
    });
    const docTitleNode = document.querySelector('title[data-i18n]');
    if (docTitleNode) {
      const dt = docTitleNode.getAttribute('data-i18n');
      if (dt) docTitleNode.textContent = t(dt);
    } else if (pageName === 'landing') {
      document.title = t('landingDocTitle');
    } else if (pageName === 'audit') {
      document.title = t('auditDocTitle');
    } else if (pageName === 'dashboard') {
      document.title = t('documentDashboardTitle');
    } else if (pageName === 'login') {
      document.title = t('loginDocTitle');
    }
  }

  function loadSavedLanguage() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored === 'en' || stored === 'ru' || stored === 'hy') {
        return stored;
      }
    } catch (err) {}
    return 'en';
  }

  function persistLanguage(lang) {
    try {
      localStorage.setItem(STORAGE_KEY, lang);
    } catch (err) {}
  }

  currentLanguage = loadSavedLanguage();
  if (languageSelect) languageSelect.value = currentLanguage;
  applyI18nToDom();

  if (languageSelect) {
    languageSelect.addEventListener('change', function () {
      currentLanguage = languageSelect.value;
      persistLanguage(currentLanguage);
      applyI18nToDom();
      if (typeof window.__monitoringRefreshLanguages === 'function') window.__monitoringRefreshLanguages();
      if (pageName === 'dashboard' && typeof window.__postDashboardUserSettings === 'function') {
        window.__postDashboardUserSettings();
      }
    });
  }

  async function jsonFetch(url, method, payload) {
    const res = await fetch(url, {
      method: method || 'GET',
      credentials: 'same-origin',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: payload ? JSON.stringify(payload) : undefined,
    });
    if (res.status === 401) {
      try {
        window.location.href = '/';
      } catch (e401) {}
      return { ok: false, status: 401, body: {} };
    }
    const body = await res.json();
    return { ok: res.ok, status: res.status, body: body };
  }

  function clearElement(el) {
    if (!el) return;
    while (el.firstChild) el.removeChild(el.firstChild);
  }

  function renderList(el, items) {
    clearElement(el);
    if (!Array.isArray(items) || items.length === 0) {
      if (el) el.textContent = t('noData');
      return;
    }
    const ul = document.createElement('ul');
    ul.style.marginTop = '10px';
    items.forEach(function (it) {
      const li = document.createElement('li');
      li.textContent = String(it);
      li.style.marginBottom = '6px';
      ul.appendChild(li);
    });
    el.appendChild(ul);
  }

  function toDatetimeLocalInputValue(dateValue) {
    const pad = function (n) {
      return String(n).padStart(2, '0');
    };
    return (
      dateValue.getFullYear() +
      '-' +
      pad(dateValue.getMonth() + 1) +
      '-' +
      pad(dateValue.getDate()) +
      'T' +
      pad(dateValue.getHours()) +
      ':' +
      pad(dateValue.getMinutes())
    );
  }

  function auditWireup() {
    const runBtn = document.getElementById('run-audit-button');
    const subnetInput = document.getElementById('subnet-input');
    const tableBody = document.getElementById('network-table-body');
    const anomalyCount = document.getElementById('anomaly-count');
    const remediationList = document.getElementById('remediation-list');
    const vulnRoot = document.getElementById('vulnerability-advisory-root');
    const rawEl = document.getElementById('audit-raw');
    if (!runBtn) return;
    runBtn.addEventListener('click', async function () {
      runBtn.disabled = true;
      const scanLoading = document.getElementById('audit-scan-loading');
      if (scanLoading) scanLoading.classList.add('active');
      try {
        clearElement(tableBody);
        if (vulnRoot) clearElement(vulnRoot);
        const payload = { language: currentLanguage };
        const subnet = subnetInput ? String(subnetInput.value || '').trim() : '';
        if (subnet) payload.subnet = subnet;
        const res = await jsonFetch('/api/audit/run', 'POST', payload);
        if (!res.ok) {
          alert('Request failed');
          return;
        }
        const sockets = res.body && res.body.scanner_results && Array.isArray(res.body.scanner_results.listening_sockets) ? res.body.scanner_results.listening_sockets : [];
        if (anomalyCount) anomalyCount.textContent = String(sockets.length);
        sockets.forEach(function (row) {
          const tr = document.createElement('tr');
          [row.ip, row.port, row.protocol, row.service_guess, row.process_name].forEach(function (v) {
            const td = document.createElement('td');
            td.textContent = v === undefined || v === null ? '' : String(v);
            tr.appendChild(td);
          });
          tableBody.appendChild(tr);
        });
        const plan = res.body && Array.isArray(res.body.remediation_plan) ? res.body.remediation_plan : [];
        const planLines = plan.map(function (p) {
          return String(p.title || '') + ': ' + String(p.resolution_steps || '');
        });
        renderList(remediationList, planLines);
        if (vulnRoot) {
          const advisories = res.body && Array.isArray(res.body.vulnerability_advisories) ? res.body.vulnerability_advisories : [];
          const hosts = window.__devaiHosts || [];
          const matchedAdvisories = filterPlaybooksForHosts(advisories, hosts, 'match_signature');
          syncAuditPlaybookPanel(matchedAdvisories.length > 0);
          if (!hosts.length || !matchedAdvisories.length) {
            vulnRoot.textContent = '';
          } else {
            matchedAdvisories.forEach(function (item) {
              const card = document.createElement('div');
              card.className = 'sentinel-panel';
              card.style.marginBottom = '12px';
              card.style.borderColor = 'rgba(124,58,237,0.45)';
              const head = document.createElement('div');
              head.style.fontWeight = '800';
              head.textContent = String(item.cve_identifier || '') + ' • ' + String(item.match_signature || '');
              const advice = document.createElement('div');
              advice.style.marginTop = '10px';
              advice.style.lineHeight = '1.5';
              advice.textContent = String(item.advice || '');
              const pre = document.createElement('pre');
              pre.className = 'sentinel-code-slab';
              const code = document.createElement('code');
              code.textContent = String(item.powershell_script || '');
              pre.appendChild(code);
              card.appendChild(head);
              card.appendChild(advice);
              card.appendChild(pre);
              vulnRoot.appendChild(card);
            });
          }
        }
        if (rawEl) rawEl.textContent = JSON.stringify(res.body, null, 2);
      } finally {
        if (scanLoading) scanLoading.classList.remove('active');
        runBtn.disabled = false;
      }
    });
  }

  function sentinelMonitoringCore() {
    const hostsBody = document.getElementById('hosts-table-body');
    const liveRoot = document.getElementById('live-dashboard-root');
    const aiAnomalyRoot = document.getElementById('ai-anomaly-root');
    const aiPredictiveRoot = document.getElementById('ai-predictive-root');
    const aiManualRoot = document.getElementById('ai-manual-root');
    const aiLegacyRoot = document.getElementById('ai-decisions');
    const refreshHosts = document.getElementById('refresh-hosts');
    const openHostCrudEmpty = document.getElementById('open-host-crud-empty');
    const hostCrudModal = document.getElementById('host-crud-modal');
    const hostCrudDismiss = document.getElementById('host-crud-dismiss');
    const hostCrudBackdrop = hostCrudModal ? hostCrudModal.querySelector('[data-host-crud-dismiss]') : null;
    const hostCrudCancel = document.getElementById('host-crud-cancel');
    const hostCrudSave = document.getElementById('host-crud-save');
    const hostCrudTitle = document.getElementById('host-crud-modal-title');
    const pollBtn = document.getElementById('poll-metrics');
    const refreshMetrics = document.getElementById('refresh-metrics');
    const refreshAi = document.getElementById('refresh-ai');
    const hostIdEl = document.getElementById('host-id');
    const hostNameEl = document.getElementById('host-hostname');
    const hostIpEl = document.getElementById('host-ip');
    const hostTypeEl = document.getElementById('host-device-type');
    const hostVendorEl = document.getElementById('host-vendor-template');
    const hostPollIntervalEl = document.getElementById('host-poll-interval');
    const hostPollProtocolEl = document.getElementById('host-poll-protocol');
    const hostMaintEl = document.getElementById('host-maintenance-mode');
    const tempHeading = document.getElementById('hosts-temperature-heading');
    const modal = document.getElementById('host-metrics-modal');
    const modalDismiss = document.getElementById('host-modal-dismiss');
    const modalBackdrop = modal ? modal.querySelector('[data-dismiss-modal]') : null;
    const modalHeading = document.getElementById('host-modal-heading');
    const metricScope = document.getElementById('host-metric-scope');
    const metricStart = document.getElementById('host-metric-start');
    const metricEnd = document.getElementById('host-metric-end');
    const metricRefresh = document.getElementById('host-metric-refresh');
    const httpBannerEl = document.getElementById('host-website-http-banner');
    const hostSshUserEl = document.getElementById('host-ssh-username');
    const hostSshPassEl = document.getElementById('host-ssh-password');
    const hostSshPortEl = document.getElementById('host-ssh-port');
    const hostSnmpCommunityEl = document.getElementById('host-snmp-community');
    const hostSnmpPortEl = document.getElementById('host-snmp-port');
    const hostSnmpVersionEl = document.getElementById('host-snmp-version');
    const snmpV2cCommunityWrapEl = document.getElementById('snmp-v2c-community-wrap');
    const snmpV3CredentialsGroupEl = document.getElementById('snmp-v3-credentials-group');
    const hostSnmpv3UserEl = document.getElementById('host-snmpv3-user');
    const hostSnmpv3AuthAlgoEl = document.getElementById('host-snmpv3-auth-algo');
    const hostSnmpv3AuthKeyEl = document.getElementById('host-snmpv3-auth-key');
    const hostSnmpv3PrivAlgoEl = document.getElementById('host-snmpv3-priv-algo');
    const hostSnmpv3PrivKeyEl = document.getElementById('host-snmpv3-priv-key');
    let chartInstance = null;
    let activeHostContext = null;
    let editingSshPasswordSet = false;
    let editingSnmpv3AuthKeySet = false;
    let editingSnmpv3PrivKeySet = false;

    function formatIntervalLabel(secondsValue) {
      var n = Number(secondsValue || 60);
      if (n === 300) {
        return '5m';
      }
      return String(n) + 's';
    }

    function syncSshCredentialsVisibility() {
      var sshGroup = document.getElementById('ssh-credentials-group');
      if (!sshGroup || !hostTypeEl) return;
      var dt = String(hostTypeEl.value || 'Server');
      if (dt === 'Switch' || dt === 'Website') {
        sshGroup.style.display = 'none';
      } else {
        sshGroup.style.display = 'grid';
      }
    }

    function syncSnmpCommunityVisibility() {
      var snmpGroup = document.getElementById('snmp-community-group');
      if (!snmpGroup || !hostPollProtocolEl) return;
      var proto = String(hostPollProtocolEl.value || 'SNMP').toUpperCase();
      if (proto !== 'SNMP') {
        snmpGroup.style.display = 'none';
        return;
      }
      snmpGroup.style.display = '';
      var verRaw = hostSnmpVersionEl ? String(hostSnmpVersionEl.value || 'v2c').toLowerCase() : 'v2c';
      if (verRaw === 'v3') {
        if (snmpV2cCommunityWrapEl) snmpV2cCommunityWrapEl.style.display = 'none';
        if (snmpV3CredentialsGroupEl) snmpV3CredentialsGroupEl.style.display = 'grid';
      } else {
        if (snmpV2cCommunityWrapEl) snmpV2cCommunityWrapEl.style.display = '';
        if (snmpV3CredentialsGroupEl) snmpV3CredentialsGroupEl.style.display = 'none';
      }
    }

    function syncHostCrudModalVisibility() {
      syncSshCredentialsVisibility();
      syncSnmpCommunityVisibility();
    }

    function openHostCrudModal(mode, hostRow) {
      if (!hostCrudModal) return;
      editingSshPasswordSet = false;
      if (mode === 'edit' && hostRow) {
        editingSshPasswordSet = !!hostRow.ssh_password_set;
        editingSnmpv3AuthKeySet = !!hostRow.snmpv3_auth_key_set;
        editingSnmpv3PrivKeySet = !!hostRow.snmpv3_priv_key_set;
        fillHostForm(hostRow);
        if (hostCrudTitle) {
          hostCrudTitle.textContent = t('editHostModal');
        }
      } else {
        editingSnmpv3AuthKeySet = false;
        editingSnmpv3PrivKeySet = false;
        clearHostForm();
        if (hostCrudTitle) {
          hostCrudTitle.textContent = t('addHostModal');
        }
      }
      hostCrudModal.classList.add('open');
      applyI18nToDom();
      syncHostCrudModalVisibility();
    }

    function closeHostCrudModal() {
      if (!hostCrudModal) return;
      hostCrudModal.classList.remove('open');
    }

    function fillHostForm(host) {
      if (hostIdEl) hostIdEl.value = String(host.id || '');
      if (hostNameEl) hostNameEl.value = String(host.hostname || '');
      if (hostIpEl) hostIpEl.value = String(host.ip_address || '');
      if (hostTypeEl) hostTypeEl.value = String(host.device_type || 'Server');
      if (hostVendorEl) hostVendorEl.value = String(host.vendor_template || 'generic_linux_net_snmp');
      var intervalSec = Number(host.polling_interval_seconds || 60);
      if (hostPollIntervalEl) {
        hostPollIntervalEl.value = [15, 30, 60, 300].indexOf(intervalSec) >= 0 ? String(intervalSec) : '60';
      }
      if (hostPollProtocolEl) {
        var proto = String(host.poll_protocol || 'SNMP').toUpperCase();
        hostPollProtocolEl.value = ['SNMP', 'SSH', 'HTTP', 'HTTPS'].indexOf(proto) >= 0 ? proto : 'SNMP';
      }
      if (hostMaintEl) hostMaintEl.checked = Number(host.maintenance_mode || 0) === 1;
      if (hostSshUserEl) hostSshUserEl.value = String(host.ssh_username || '');
      if (hostSshPassEl) hostSshPassEl.value = '';
      if (hostSshPortEl) hostSshPortEl.value = String(host.ssh_port != null ? host.ssh_port : 22);
      if (hostSnmpCommunityEl) {
        var sc = host.snmp_community;
        hostSnmpCommunityEl.value =
          sc !== undefined && sc !== null && String(sc).length ? String(sc) : 'public';
      }
      if (hostSnmpPortEl) {
        var sp = host.snmp_port;
        var spin = Number(sp != null ? sp : 161);
        hostSnmpPortEl.value = String(!isNaN(spin) && spin > 0 && spin <= 65535 ? spin : 161);
      }
      if (hostSnmpVersionEl) {
        var sv = String(host.snmp_version || 'v2c').toLowerCase();
        hostSnmpVersionEl.value = sv === 'v3' ? 'v3' : 'v2c';
      }
      if (hostSnmpv3UserEl) hostSnmpv3UserEl.value = String(host.snmpv3_user || '');
      if (hostSnmpv3AuthAlgoEl) {
        var aa = String(host.snmpv3_auth_algo || 'SHA').toUpperCase();
        hostSnmpv3AuthAlgoEl.value = aa === 'MD5' ? 'MD5' : 'SHA';
      }
      if (hostSnmpv3PrivAlgoEl) {
        var pa = String(host.snmpv3_priv_algo || 'AES').toUpperCase();
        hostSnmpv3PrivAlgoEl.value = pa === 'DES' ? 'DES' : 'AES';
      }
      if (hostSnmpv3AuthKeyEl) hostSnmpv3AuthKeyEl.value = '';
      if (hostSnmpv3PrivKeyEl) hostSnmpv3PrivKeyEl.value = '';
    }

    function clearHostForm() {
      if (hostIdEl) hostIdEl.value = '';
      if (hostNameEl) hostNameEl.value = '';
      if (hostIpEl) hostIpEl.value = '';
      if (hostTypeEl) hostTypeEl.value = 'Server';
      if (hostVendorEl) hostVendorEl.value = 'generic_linux_net_snmp';
      if (hostPollIntervalEl) hostPollIntervalEl.value = '60';
      if (hostPollProtocolEl) hostPollProtocolEl.value = 'SNMP';
      if (hostMaintEl) hostMaintEl.checked = false;
      if (hostSshUserEl) hostSshUserEl.value = '';
      if (hostSshPassEl) hostSshPassEl.value = '';
      if (hostSshPortEl) hostSshPortEl.value = '22';
      if (hostSnmpCommunityEl) hostSnmpCommunityEl.value = 'public';
      if (hostSnmpPortEl) hostSnmpPortEl.value = '161';
      if (hostSnmpVersionEl) hostSnmpVersionEl.value = 'v2c';
      if (hostSnmpv3UserEl) hostSnmpv3UserEl.value = '';
      if (hostSnmpv3AuthAlgoEl) hostSnmpv3AuthAlgoEl.value = 'SHA';
      if (hostSnmpv3AuthKeyEl) hostSnmpv3AuthKeyEl.value = '';
      if (hostSnmpv3PrivAlgoEl) hostSnmpv3PrivAlgoEl.value = 'AES';
      if (hostSnmpv3PrivKeyEl) hostSnmpv3PrivKeyEl.value = '';
    }

    function statusClass(statusValue) {
      return String(statusValue).toLowerCase() === 'offline' ? 'warn' : 'good';
    }

    function isMetricRowOffline(metricRow) {
      return String(metricRow.status || '').toLowerCase() === 'offline';
    }

    function liveStatusTone(metricRow) {
      if (Number(metricRow.maintenance_mode || 0) === 1 || String(metricRow.status || '').toLowerCase() === 'paused') {
        return 'paused';
      }
      var rawStatus = String(metricRow.status || '').toLowerCase();
      if (rawStatus === 'offline') {
        return 'offline';
      }
      if (rawStatus === 'degraded') {
        return 'warn';
      }
      return 'good';
    }

    function httpStatusPhrase(code) {
      if (code === null || code === undefined || code === '') {
        return '—';
      }
      var n = Number(code);
      var map = {
        200: 'OK',
        201: 'Created',
        204: 'No Content',
        301: 'Moved',
        302: 'Found',
        400: 'Bad Request',
        401: 'Unauthorized',
        403: 'Forbidden',
        404: 'Not Found',
        500: 'Server Error',
        502: 'Bad Gateway',
        503: 'Unavailable',
      };
      return String(n) + ' ' + (map[n] || '');
    }

    function formatMetricDisplay(value) {
      if (value === null || value === undefined || value === '') {
        return t('metricNA');
      }
      return String(value);
    }

    function buildMetricRow(label, numericValue, tone) {
      const row = document.createElement('div');
      row.className = 'sentinel-metric-chip ' + (tone || 'good');
      const left = document.createElement('span');
      left.textContent = label;
      const right = document.createElement('span');
      right.dataset.metricValue = '1';
      right.textContent = formatMetricDisplay(numericValue);
      row.appendChild(left);
      row.appendChild(right);
      return row;
    }

    function groupBuckets(rows) {
      const servers = [];
      const switches = [];
      const vms = [];
      const websites = [];
      rows.forEach(function (row) {
        const kind = String(row.device_type || '');
        if (kind === 'Switch') switches.push(row);
        else if (kind === 'VM') vms.push(row);
        else if (kind === 'Website') websites.push(row);
        else servers.push(row);
      });
      return { servers: servers, switches: switches, vms: vms, websites: websites };
    }

    function buildClusterSection(titleKey, accentClass, subset) {
      if (!subset.length) return null;
      const wrap = document.createElement('section');
      wrap.className = 'sentinel-live-cluster ' + accentClass + ' sentinel-fade-up';
      const title = document.createElement('div');
      title.className = 'sentinel-cluster-title';
      title.textContent = t(titleKey);
      const grid = document.createElement('div');
      grid.className = 'sentinel-metrics-grid';
      subset.forEach(function (metricRow, staggerIndex) {
        const card = document.createElement('article');
        card.className = 'sentinel-live-card sentinel-action-scale';
        card.style.animationDelay = staggerIndex * 60 + 'ms';
        card.dataset.hostId = String(metricRow.host_id);
        card.dataset.deviceType = String(metricRow.device_type || '');
        card.addEventListener('click', function () {
          openInsightModal(metricRow);
        });
        const metaRow = document.createElement('div');
        metaRow.className = 'sentinel-live-meta';
        const hostname = document.createElement('div');
        hostname.className = 'sentinel-live-title';
        hostname.textContent = String(metricRow.hostname || '');
        const ipLabel = document.createElement('div');
        ipLabel.textContent = String(metricRow.ip_address || '');
        metaRow.appendChild(hostname);
        metaRow.appendChild(ipLabel);
        const statusRow = document.createElement('div');
        statusRow.className = 'sentinel-live-status';
        const tone = liveStatusTone(metricRow);
        const dot = document.createElement('span');
        dot.className =
          'sentinel-pulse-dot ' +
          (tone === 'offline'
            ? 'sentinel-pulse-host-down'
            : tone === 'paused' || tone === 'warn'
            ? 'sentinel-pulse-offline'
            : 'sentinel-pulse-online');
        const statusIcon = document.createElement('i');
        statusIcon.setAttribute('aria-hidden', 'true');
        if (tone === 'paused') {
          statusIcon.className = 'fa-solid fa-circle-pause fa-fw';
          statusIcon.style.color = 'var(--text-muted)';
        } else if (tone === 'offline') {
          statusIcon.className = 'fa-solid fa-circle-xmark fa-fw sentinel-status-ico-critical-offline';
        } else if (tone === 'warn') {
          statusIcon.className = 'fa-solid fa-triangle-exclamation fa-fw sentinel-status-ico-warn';
        } else {
          statusIcon.className = 'fa-solid fa-circle-check fa-fw sentinel-status-ico-ok';
        }
        const statusCaption = document.createElement('span');
        statusCaption.textContent =
          tone === 'paused' ? t('statusPaused') : tone === 'offline' ? t('statusOffline') : String(metricRow.status || 'unknown');
        statusRow.appendChild(dot);
        statusRow.appendChild(statusIcon);
        statusRow.appendChild(statusCaption);
        const statusWrap = document.createElement('div');
        statusWrap.className = 'devai-status-block';
        statusWrap.appendChild(statusRow);
        if (tone === 'offline' && String(metricRow.last_error_message || '').trim()) {
          const errSub = document.createElement('div');
          errSub.className = 'devai-offline-error-subtitle';
          errSub.textContent = String(metricRow.last_error_message || '').trim();
          statusWrap.appendChild(errSub);
        }
        const metricWrap = document.createElement('div');
        metricWrap.className = 'sentinel-metric-rows';
        if (String(metricRow.device_type) === 'Website') {
          if (isMetricRowOffline(metricRow)) {
            const offlineWebsite = document.createElement('div');
            offlineWebsite.className = 'sentinel-live-metrics-unavailable';
            offlineWebsite.textContent = t('statusOffline');
            metricWrap.appendChild(offlineWebsite);
            if (String(metricRow.last_error_message || '').trim()) {
              const errDetail = document.createElement('div');
              errDetail.className = 'devai-offline-error-subtitle';
              errDetail.textContent = String(metricRow.last_error_message || '').trim();
              metricWrap.appendChild(errDetail);
            }
          } else {
            const gaugeWrap = document.createElement('div');
            gaugeWrap.style.marginTop = '10px';
            const gaugeLabel = document.createElement('div');
            gaugeLabel.style.fontSize = '0.72rem';
            gaugeLabel.style.color = 'var(--text-muted)';
            gaugeLabel.style.marginBottom = '4px';
            gaugeLabel.textContent = t('responseTimeMs');
            const barOuter = document.createElement('div');
            barOuter.style.height = '10px';
            barOuter.style.borderRadius = '999px';
            barOuter.style.background = 'rgba(255,255,255,0.08)';
            barOuter.style.overflow = 'hidden';
            const barInner = document.createElement('div');
            var msVal = metricRow.latency_ms === null || metricRow.latency_ms === undefined ? 0 : Number(metricRow.latency_ms);
            var pct = Math.min(100, Math.round((msVal / 3000) * 100));
            barInner.style.width = pct + '%';
            barInner.style.height = '100%';
            barInner.style.background = 'linear-gradient(90deg,#22d3ee,#7c3aed)';
            barOuter.appendChild(barInner);
            const msReadout = document.createElement('div');
            msReadout.style.marginTop = '6px';
            msReadout.style.fontSize = '1.05rem';
            msReadout.style.fontWeight = '800';
            msReadout.textContent =
              metricRow.latency_ms === null || metricRow.latency_ms === undefined ? t('metricNA') : String(metricRow.latency_ms) + ' ms';
            const badge = document.createElement('div');
            badge.style.marginTop = '10px';
            badge.style.display = 'inline-block';
            badge.style.padding = '6px 12px';
            badge.style.borderRadius = '10px';
            badge.style.fontWeight = '800';
            badge.style.fontSize = '0.8rem';
            var codeNum = metricRow.http_status_code === null || metricRow.http_status_code === undefined ? null : Number(metricRow.http_status_code);
            badge.textContent = httpStatusPhrase(codeNum);
            if (codeNum !== null && !isNaN(codeNum) && codeNum >= 200 && codeNum < 400) {
              badge.style.background = 'rgba(34,197,94,0.2)';
              badge.style.color = '#4ade80';
              badge.style.border = '1px solid rgba(74,222,128,0.5)';
            } else if (codeNum !== null && !isNaN(codeNum) && codeNum >= 400 && codeNum < 500) {
              badge.style.background = 'rgba(251,191,36,0.15)';
              badge.style.color = '#fbbf24';
              badge.style.border = '1px solid rgba(251,191,36,0.45)';
            } else if (codeNum !== null && !isNaN(codeNum)) {
              badge.style.background = 'rgba(248,113,113,0.15)';
              badge.style.color = '#f87171';
              badge.style.border = '1px solid rgba(248,113,113,0.45)';
            } else {
              badge.style.background = 'rgba(148,163,184,0.15)';
              badge.style.color = 'var(--text-muted)';
              badge.style.border = '1px solid rgba(148,163,184,0.25)';
            }
            gaugeWrap.appendChild(gaugeLabel);
            gaugeWrap.appendChild(barOuter);
            gaugeWrap.appendChild(msReadout);
            metricWrap.appendChild(gaugeWrap);
            metricWrap.appendChild(badge);
          }
        } else if (isMetricRowOffline(metricRow)) {
          const offlineBlock = document.createElement('div');
          offlineBlock.className = 'sentinel-live-metrics-unavailable';
          offlineBlock.textContent = t('statusOffline');
          metricWrap.appendChild(offlineBlock);
          if (String(metricRow.last_error_message || '').trim()) {
            const errDetail = document.createElement('div');
            errDetail.className = 'devai-offline-error-subtitle';
            errDetail.textContent = String(metricRow.last_error_message || '').trim();
            metricWrap.appendChild(errDetail);
          }
        } else {
          metricWrap.appendChild(buildMetricRow(t('cpu'), metricRow.cpu_utilization, statusClass(metricRow.status)));
          metricWrap.appendChild(buildMetricRow(t('ram'), metricRow.ram_usage, 'good'));
          var diskNum = metricRow.disk_usage;
          var diskTone = diskNum !== null && diskNum !== undefined && Number(diskNum) > 90 ? 'warn' : 'good';
          metricWrap.appendChild(buildMetricRow(t('disk'), diskNum, diskTone));
          if (String(metricRow.device_type) !== 'VM') {
            metricWrap.appendChild(buildMetricRow(t('temp'), metricRow.temperature_c, 'good'));
          }
        }
        const slaRow = document.createElement('div');
        slaRow.style.marginTop = '8px';
        slaRow.style.fontSize = '0.72rem';
        slaRow.style.color = 'var(--text-muted)';
        slaRow.textContent =
          t('slaUptimeLabel') +
          ': ' +
          (metricRow.sla_uptime_percent !== undefined && metricRow.sla_uptime_percent !== null ? String(metricRow.sla_uptime_percent) + '%' : '—');
        const polled = document.createElement('div');
        polled.style.marginTop = '10px';
        polled.style.fontSize = '0.75rem';
        polled.style.color = 'var(--text-muted)';
        polled.textContent = t('polledAt') + ': ' + String(metricRow.polled_at || '');
        card.appendChild(metaRow);
        card.appendChild(statusWrap);
        card.appendChild(metricWrap);
        card.appendChild(slaRow);
        card.appendChild(polled);
        grid.appendChild(card);
      });
      wrap.appendChild(title);
      wrap.appendChild(grid);
      return wrap;
    }

    function renderLive(groups) {
      if (!liveRoot) return;
      clearElement(liveRoot);
      const buckets = [
        ['heatClusterServers', 'sentinel-cluster-servers', groups.servers],
        ['heatClusterSwitches', 'sentinel-cluster-switches', groups.switches],
        ['heatClusterVms', 'sentinel-cluster-vms', groups.vms],
        ['heatClusterWebsites', 'sentinel-cluster-websites', groups.websites],
      ];
      buckets.forEach(function (triple) {
        const node = buildClusterSection(triple[0], triple[1], triple[2]);
        if (node) liveRoot.appendChild(node);
      });
      if (!liveRoot.children.length) {
        liveRoot.textContent = t('noData');
      }
    }

    function hydrateMetricPickers(deviceKind) {
      if (!metricScope) return;
      clearElement(metricScope);
      if (String(deviceKind) === 'Website') {
        const opt = document.createElement('option');
        opt.value = 'latency_ms';
        opt.textContent = t('responseTimeMs');
        metricScope.appendChild(opt);
        return;
      }
      const catalog = [];
      catalog.push({ value: 'cpu_utilization', label: t('cpu') });
      catalog.push({ value: 'ram_usage', label: t('ram') });
      catalog.push({ value: 'disk_usage', label: t('disk') });
      if (String(deviceKind) !== 'VM') {
        catalog.push({ value: 'temperature_c', label: t('temp') });
      }
      catalog.forEach(function (entry) {
        const opt = document.createElement('option');
        opt.value = entry.value;
        opt.textContent = entry.label;
        metricScope.appendChild(opt);
      });
    }

    function closeModalSurface() {
      if (!modal) return;
      modal.classList.remove('open');
      if (httpBannerEl) {
        httpBannerEl.style.display = 'none';
        httpBannerEl.textContent = '';
      }
      if (chartInstance) {
        chartInstance.destroy();
        chartInstance = null;
      }
      activeHostContext = null;
    }

    function openInsightModal(hostSnapshot) {
      if (!modal) return;
      activeHostContext = hostSnapshot;
      modal.classList.add('open');
      if (modalHeading) modalHeading.textContent = String(hostSnapshot.hostname || '') + ' • ' + String(hostSnapshot.ip_address || '');
      hydrateMetricPickers(hostSnapshot.device_type);
      if (httpBannerEl) {
        if (String(hostSnapshot.device_type) === 'Website') {
          httpBannerEl.style.display = '';
          var c0 = hostSnapshot.http_status_code === null || hostSnapshot.http_status_code === undefined ? null : Number(hostSnapshot.http_status_code);
          httpBannerEl.textContent = t('httpStatusShort') + ': ' + httpStatusPhrase(c0);
          if (c0 !== null && !isNaN(c0) && c0 >= 200 && c0 < 400) {
            httpBannerEl.style.color = '#4ade80';
          } else if (c0 !== null && !isNaN(c0) && c0 >= 400 && c0 < 500) {
            httpBannerEl.style.color = '#fbbf24';
          } else if (c0 !== null && !isNaN(c0)) {
            httpBannerEl.style.color = '#f87171';
          } else {
            httpBannerEl.style.color = 'var(--text-muted)';
          }
        } else {
          httpBannerEl.style.display = 'none';
          httpBannerEl.textContent = '';
        }
      }
      const horizon = new Date();
      const past = new Date(horizon.getTime() - 72 * 3600 * 1000);
      if (metricEnd) metricEnd.value = toDatetimeLocalInputValue(horizon);
      if (metricStart) metricStart.value = toDatetimeLocalInputValue(past);
      loadHistorySeries();
    }

    async function loadHistorySeries() {
      if (!activeHostContext || typeof Chart === 'undefined') return;
      const canvas = document.getElementById('host-metric-chart');
      const hostIdNumeric = Number(activeHostContext.host_id || 0);
      const payload = {
        host_id: hostIdNumeric,
        start: metricStart ? metricStart.value : null,
        end: metricEnd ? metricEnd.value : null,
      };
      const res = await jsonFetch('/api/metrics/history', 'POST', payload);
      if (!res.ok) return;
      const rows = res.body && Array.isArray(res.body.series) ? res.body.series : [];
      const fieldKey = metricScope ? metricScope.value : 'cpu_utilization';
      var labelText = fieldKey;
      if (metricScope && metricScope.selectedOptions && metricScope.selectedOptions[0]) {
        labelText = metricScope.selectedOptions[0].textContent;
      }
      const labels = rows.map(function (pt) {
        return String(pt.polled_at || '');
      });
      const values = rows.map(function (pt) {
        var rawPiece = pt[fieldKey];
        if (rawPiece === null || rawPiece === undefined) return null;
        return Number(rawPiece);
      });
      if (httpBannerEl && activeHostContext && String(activeHostContext.device_type) === 'Website' && rows.length) {
        var lastPt = rows[rows.length - 1];
        var c1 = lastPt.http_status_code === null || lastPt.http_status_code === undefined ? null : Number(lastPt.http_status_code);
        httpBannerEl.style.display = '';
        httpBannerEl.textContent = t('httpStatusShort') + ': ' + httpStatusPhrase(c1);
        if (c1 !== null && !isNaN(c1) && c1 >= 200 && c1 < 400) {
          httpBannerEl.style.color = '#4ade80';
        } else if (c1 !== null && !isNaN(c1) && c1 >= 400 && c1 < 500) {
          httpBannerEl.style.color = '#fbbf24';
        } else if (c1 !== null && !isNaN(c1)) {
          httpBannerEl.style.color = '#f87171';
        } else {
          httpBannerEl.style.color = 'var(--text-muted)';
        }
      }
      if (chartInstance) chartInstance.destroy();
      if (!canvas) return;
      chartInstance = new Chart(canvas.getContext('2d'), {
        type: 'line',
        data: {
          labels: labels,
          datasets: [
            {
              label: labelText,
              data: values,
              tension: 0.35,
              borderColor: '#7c3aed',
              backgroundColor: 'rgba(124,58,237,0.15)',
              fill: true,
              spanGaps: true,
              pointRadius: 3,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: {
            intersect: false,
            mode: 'index',
          },
          plugins: {
            legend: { labels: { color: '#e2e8f0' } },
          },
          scales: {
            x: {
              ticks: { color: '#cbd5f5', maxRotation: 0 },
              grid: { color: 'rgba(148,163,184,0.12)' },
            },
            y: {
              ticks: { color: '#cbd5f5' },
              grid: { color: 'rgba(148,163,184,0.12)' },
              suggestedMin: 0,
              suggestedMax: 100,
            },
          },
        },
      });
    }

    async function loadHosts() {
      if (!hostsBody) return;
      const res = await jsonFetch('/api/hosts', 'GET');
      if (!res.ok) return;
      const packMetrics = await jsonFetch('/api/metrics/latest', 'GET');
      clearElement(hostsBody);
      const hosts = res.body && Array.isArray(res.body.hosts) ? res.body.hosts : [];
      window.__devaiHosts = hosts;
      syncAuditPlaybookPanel(false);
      syncManualPlaybookPanel(false);
      const metricsRows = packMetrics.ok && packMetrics.body && Array.isArray(packMetrics.body.metrics) ? packMetrics.body.metrics : [];
      const telemetryIndex = {};
      metricsRows.forEach(function (snapshot) {
        telemetryIndex[String(snapshot.host_id)] = snapshot;
      });
      const hasThermal = hosts.some(function (candidate) {
        var dk = String(candidate.device_type || '');
        return dk !== 'VM' && dk !== 'Website';
      });
      if (tempHeading) {
        tempHeading.style.display = hasThermal ? '' : 'none';
      }
      hosts.forEach(function (hostRow, hostIndex) {
        const tr = document.createElement('tr');
        ;[
          hostIndex + 1,
          hostRow.hostname,
          hostRow.ip_address,
          hostRow.vendor_template,
          hostRow.device_type,
          formatIntervalLabel(hostRow.polling_interval_seconds),
          hostRow.poll_protocol,
        ].forEach(function (columnValue) {
          const td = document.createElement('td');
          td.textContent = columnValue === undefined || columnValue === null ? '' : String(columnValue);
          tr.appendChild(td);
        });
        if (hasThermal) {
          const thermalCell = document.createElement('td');
          if (String(hostRow.device_type) === 'VM' || String(hostRow.device_type) === 'Website') {
            thermalCell.className = 'sentinel-vm-thermal-skip';
            thermalCell.textContent = '—';
          } else {
            const snap = telemetryIndex[String(hostRow.id)];
            thermalCell.textContent = snap && snap.temperature_c !== null && snap.temperature_c !== undefined ? String(snap.temperature_c) : '';
          }
          tr.appendChild(thermalCell);
        }
        ;[hostRow.date_added].forEach(function (columnValue) {
          const td = document.createElement('td');
          td.textContent = columnValue === undefined || columnValue === null ? '' : String(columnValue);
          tr.appendChild(td);
        });
        const tdActions = document.createElement('td');
        const editBtn = document.createElement('button');
        editBtn.textContent = t('edit');
        editBtn.className = 'sentinel-chip-btn sentinel-chip-ghost sentinel-action-scale';
        editBtn.addEventListener('click', function () {
          openHostCrudModal('edit', hostRow);
          if (typeof window.__activateDashboardView === 'function') window.__activateDashboardView('hosts');
        });
        const delBtn = document.createElement('button');
        delBtn.textContent = t('delete');
        delBtn.className = 'sentinel-chip-btn sentinel-chip-warn sentinel-action-scale';
        delBtn.style.marginLeft = '6px';
        delBtn.addEventListener('click', async function () {
          const resDel = await jsonFetch('/api/hosts', 'DELETE', { id: hostRow.id });
          if (resDel.ok) await loadHosts();
        });
        tdActions.appendChild(editBtn);
        tdActions.appendChild(delBtn);
        tr.appendChild(tdActions);
        hostsBody.appendChild(tr);
      });
    }

    async function saveHostCrudAction() {
      const hid = hostIdEl ? Number(hostIdEl.value || 0) : 0;
      const payload = {
        hostname: hostNameEl ? String(hostNameEl.value || '').trim() : '',
        ip_address: hostIpEl ? String(hostIpEl.value || '').trim() : '',
        device_type: hostTypeEl ? hostTypeEl.value : 'Server',
        vendor_template: hostVendorEl ? hostVendorEl.value : 'generic_linux_net_snmp',
        polling_interval_seconds: hostPollIntervalEl ? Number(hostPollIntervalEl.value || 60) : 60,
        poll_protocol: hostPollProtocolEl ? String(hostPollProtocolEl.value || 'SNMP') : 'SNMP',
        ssh_username: hostSshUserEl ? String(hostSshUserEl.value || '').trim() : '',
        ssh_password: hostSshPassEl ? String(hostSshPassEl.value || '') : '',
        ssh_port: hostSshPortEl ? Number(hostSshPortEl.value || 22) : 22,
        snmp_community: hostSnmpCommunityEl
          ? String(hostSnmpCommunityEl.value || '').trim() || 'public'
          : 'public',
        snmp_port: hostSnmpPortEl ? Number(hostSnmpPortEl.value || 161) : 161,
        snmp_version: hostSnmpVersionEl ? String(hostSnmpVersionEl.value || 'v2c') : 'v2c',
        snmpv3_user: hostSnmpv3UserEl ? String(hostSnmpv3UserEl.value || '').trim() : '',
        snmpv3_auth_algo: hostSnmpv3AuthAlgoEl ? String(hostSnmpv3AuthAlgoEl.value || 'SHA') : 'SHA',
        snmpv3_auth_key: hostSnmpv3AuthKeyEl ? String(hostSnmpv3AuthKeyEl.value || '') : '',
        snmpv3_priv_algo: hostSnmpv3PrivAlgoEl ? String(hostSnmpv3PrivAlgoEl.value || 'AES') : 'AES',
        snmpv3_priv_key: hostSnmpv3PrivKeyEl ? String(hostSnmpv3PrivKeyEl.value || '') : '',
        maintenance_mode: hostMaintEl && hostMaintEl.checked ? 1 : 0,
      };
      var deviceKindSave = hostTypeEl ? String(hostTypeEl.value || 'Server') : 'Server';
      var pollProtoSave = hostPollProtocolEl ? String(hostPollProtocolEl.value || 'SNMP').toUpperCase() : 'SNMP';
      if (
        hid > 0 &&
        editingSshPasswordSet &&
        hostSshPassEl &&
        !String(hostSshPassEl.value || '').trim() &&
        deviceKindSave !== 'Switch' &&
        deviceKindSave !== 'Website'
      ) {
        payload.preserve_ssh_password = true;
      }
      if (
        hid > 0 &&
        pollProtoSave === 'SNMP' &&
        String(payload.snmp_version || 'v2c').toLowerCase() === 'v3' &&
        editingSnmpv3AuthKeySet &&
        hostSnmpv3AuthKeyEl &&
        !String(hostSnmpv3AuthKeyEl.value || '').trim()
      ) {
        payload.preserve_snmpv3_auth_key = true;
      }
      if (
        hid > 0 &&
        pollProtoSave === 'SNMP' &&
        String(payload.snmp_version || 'v2c').toLowerCase() === 'v3' &&
        editingSnmpv3PrivKeySet &&
        hostSnmpv3PrivKeyEl &&
        !String(hostSnmpv3PrivKeyEl.value || '').trim()
      ) {
        payload.preserve_snmpv3_priv_key = true;
      }
      let res;
      if (hid > 0) {
        res = await jsonFetch('/api/hosts/' + hid, 'PUT', payload);
      } else {
        res = await jsonFetch('/api/hosts', 'POST', payload);
      }
      if (res.ok) {
        closeHostCrudModal();
        clearHostForm();
        await loadHosts();
      } else {
        alert('Request failed');
      }
    }

    async function loadMetricsLatest() {
      const res = await jsonFetch('/api/metrics/latest', 'GET');
      if (!res.ok) return;
      const rows = res.body && Array.isArray(res.body.metrics) ? res.body.metrics : [];
      renderLive(groupBuckets(rows));
    }

    async function pollMetrics() {
      const pollLoading = document.getElementById('snmp-poll-loading');
      if (pollLoading) pollLoading.classList.add('active');
      try {
        const resPoll = await jsonFetch('/api/metrics/poll', 'POST', {});
        if (!resPoll.ok) return;
        await loadMetricsLatest();
      } finally {
        if (pollLoading) pollLoading.classList.remove('active');
      }
    }

    function appendDecisionCard(rootEl, d, forcePredictiveClass) {
      if (!rootEl) return;
      const panel = document.createElement('article');
      panel.className = 'sentinel-ai-card sentinel-fade-up';
      const h = document.createElement('h3');
      const icon = document.createElement('i');
      icon.className = 'fa-solid fa-server fa-fw';
      icon.setAttribute('aria-hidden', 'true');
      h.appendChild(icon);
      h.appendChild(
        document.createTextNode(
          ' ' +
            String(d.hostname || '') +
            ' (' +
            String(d.ip_address || '') +
            ') • ' +
            String(d.vendor_template || '—') +
            ' • ' +
            String(d.title || '')
        )
      );
      const narrative = document.createElement('div');
      narrative.className = 'sentinel-ai-block devai-ai-narrative';
      narrative.appendChild(formatAiNarrative(String(d.trend_analysis || '')));
      if (forcePredictiveClass || d.predictive_alert) {
        narrative.classList.add('sentinel-ai-predictive');
      }
      const pre = document.createElement('pre');
      pre.className = 'sentinel-code-slab';
      const code = document.createElement('code');
      code.textContent = String(d.script || '');
      pre.appendChild(code);
      panel.appendChild(h);
      panel.appendChild(narrative);
      if (String(d.resolution_text || '').trim()) {
        const playbook = document.createElement('div');
        playbook.className = 'sentinel-ai-block devai-ai-playbook';
        playbook.appendChild(formatAiNarrative(String(d.resolution_text || '')));
        panel.appendChild(playbook);
      }
      panel.appendChild(pre);
      var cmdText = String(d.script || '').trim();
      if (cmdText && d.host_id && window.__devaiRole === 'Admin') {
        var deployBtn = document.createElement('button');
        deployBtn.type = 'button';
        deployBtn.className = 'sentinel-deploy-ssh-btn';
        deployBtn.textContent = t('deploySsh');
        deployBtn.addEventListener('click', async function (ev) {
          ev.stopPropagation();
          var resExec = await jsonFetch('/api/execute_remediation', 'POST', {
            host_id: Number(d.host_id),
            command_string: cmdText,
          });
          if (resExec.ok && resExec.body && resExec.body.ok) {
            showDevAIToast(t('toastSshOk'), false);
          } else {
            showDevAIToast(t('toastSshFail'), true);
          }
        });
        panel.appendChild(deployBtn);
      }
      rootEl.appendChild(panel);
    }

    function setRootEmptyState(rootEl) {
      if (!rootEl) return;
      clearElement(rootEl);
      rootEl.textContent = t('noData');
    }

    async function loadAiDecisions() {
      const res = await jsonFetch('/api/ai/decisions', 'POST', { language: currentLanguage });
      if (!res.ok) return;
      const useSplit = !!(aiAnomalyRoot || aiPredictiveRoot || aiManualRoot);
      if (useSplit) {
        if (aiAnomalyRoot) clearElement(aiAnomalyRoot);
        if (aiPredictiveRoot) clearElement(aiPredictiveRoot);
        if (aiManualRoot) clearElement(aiManualRoot);
      } else if (aiLegacyRoot) {
        clearElement(aiLegacyRoot);
      }
      var anomalyPack = res.body && Array.isArray(res.body.anomaly_alerts) ? res.body.anomaly_alerts : null;
      var predictivePack = res.body && Array.isArray(res.body.predictive_alerts) ? res.body.predictive_alerts : null;
      var manualPack = res.body && Array.isArray(res.body.manual_suggestions) ? res.body.manual_suggestions : [];
      var hostsForManuals = window.__devaiHosts || [];
      manualPack = filterPlaybooksForHosts(manualPack, hostsForManuals, 'title');
      syncManualPlaybookPanel(manualPack.length > 0);
      if (anomalyPack === null && res.body && Array.isArray(res.body.decisions)) {
        var legacyAll = res.body.decisions;
        anomalyPack = legacyAll.filter(function (x) {
          return !x.predictive_alert;
        });
        predictivePack = legacyAll.filter(function (x) {
          return x.predictive_alert;
        });
      }
      if (anomalyPack === null) anomalyPack = [];
      if (predictivePack === null) predictivePack = [];
      if (useSplit) {
        if (!anomalyPack.length) {
          setRootEmptyState(aiAnomalyRoot);
        } else {
          anomalyPack.forEach(function (d) {
            appendDecisionCard(aiAnomalyRoot, d, false);
          });
        }
        if (!predictivePack.length) {
          setRootEmptyState(aiPredictiveRoot);
        } else {
          predictivePack.forEach(function (d) {
            appendDecisionCard(aiPredictiveRoot, d, true);
          });
        }
        if (!manualPack.length) {
          if (aiManualRoot) clearElement(aiManualRoot);
        } else {
          manualPack.forEach(function (s) {
            const panel = document.createElement('article');
            panel.className = 'sentinel-ai-card sentinel-fade-up';
            const h = document.createElement('h3');
            const bookIcon = document.createElement('i');
            bookIcon.className = 'fa-solid fa-book fa-fw';
            bookIcon.setAttribute('aria-hidden', 'true');
            h.appendChild(bookIcon);
            h.appendChild(document.createTextNode(' ' + String(s.title || s.source_key || '')));
            const body = document.createElement('div');
            body.className = 'sentinel-ai-block devai-ai-narrative';
            body.appendChild(formatAiNarrative(String(s.guidance || '')));
            const score = document.createElement('div');
            score.className = 'sentinel-ai-block';
            score.style.fontSize = '0.78rem';
            score.style.color = 'var(--text-muted)';
            score.textContent = t('manualScoreLabel') + ': ' + (Math.round(Number(s.similarity_score || 0) * 1000) / 1000);
            panel.appendChild(h);
            panel.appendChild(body);
            panel.appendChild(score);
            aiManualRoot.appendChild(panel);
          });
        }
      } else if (aiLegacyRoot) {
        var merged = anomalyPack.concat(predictivePack);
        if (!merged.length) {
          aiLegacyRoot.textContent = t('noData');
          return;
        }
        merged.forEach(function (d) {
          appendDecisionCard(aiLegacyRoot, d, false);
        });
      }
    }

    window.__monitoringRefreshLanguages = async function () {
      await loadHosts();
      await loadMetricsLatest();
      await loadAiDecisions();
      applyI18nToDom();
      await loadHistorySeries().catch(function () {});
    };

    if (refreshHosts) refreshHosts.addEventListener('click', loadHosts);
    if (openHostCrudEmpty) openHostCrudEmpty.addEventListener('click', function () {
      openHostCrudModal('create', null);
    });
    if (hostCrudSave) hostCrudSave.addEventListener('click', saveHostCrudAction);
    if (hostCrudCancel) hostCrudCancel.addEventListener('click', closeHostCrudModal);
    if (hostCrudDismiss) hostCrudDismiss.addEventListener('click', closeHostCrudModal);
    if (hostCrudBackdrop) hostCrudBackdrop.addEventListener('click', closeHostCrudModal);
    if (hostTypeEl) hostTypeEl.addEventListener('change', syncHostCrudModalVisibility);
    if (hostPollProtocolEl) hostPollProtocolEl.addEventListener('change', syncHostCrudModalVisibility);
    if (hostSnmpVersionEl) hostSnmpVersionEl.addEventListener('change', syncHostCrudModalVisibility);
    if (pollBtn) pollBtn.addEventListener('click', pollMetrics);
    if (refreshMetrics) refreshMetrics.addEventListener('click', loadMetricsLatest);
    if (refreshAi) refreshAi.addEventListener('click', loadAiDecisions);
    if (metricRefresh) metricRefresh.addEventListener('click', loadHistorySeries);
    if (metricScope) metricScope.addEventListener('change', loadHistorySeries);
    if (modalDismiss) modalDismiss.addEventListener('click', closeModalSurface);
    if (modalBackdrop) modalBackdrop.addEventListener('click', closeModalSurface);
    window.addEventListener('keydown', function (evt) {
      if (evt.key === 'Escape') {
        closeModalSurface();
        closeHostCrudModal();
      }
    });

    window.addEventListener('pageshow', function () {
      if (pageName !== 'monitoring' && pageName !== 'dashboard') return;
      loadHosts().then(function () {
        loadMetricsLatest();
        loadAiDecisions();
      });
    });

    loadHosts().then(function () {
      loadMetricsLatest();
      loadAiDecisions();
    });
  }

  async function dashboardWireup() {
    const appShell = document.getElementById('sentinel-dashboard-app');
    const navBtns = document.querySelectorAll('.sentinel-dash-nav');
    const panels = document.querySelectorAll('.sentinel-dashboard-panel');
    const themeSelect = document.getElementById('theme-select');
    const collapseBtn = document.getElementById('sidebar-collapse-toggle');
    const alertRefresh = document.getElementById('refresh-alert-logs');
    const profileForm = document.getElementById('profile-password-form');
    const systemSave = document.getElementById('system-settings-save');
    const systemStatus = document.getElementById('system-settings-status');
    function normalizeDashTheme(v) {
      if (v === 'slate_dark' || v === 'light') return v;
      return 'vibrant_dark';
    }
    function normalizeClientLanguage(v) {
      var x = String(v || 'en');
      return x === 'ru' || x === 'hy' ? x : 'en';
    }
    function applyThemeToBody(themeValue) {
      var v = normalizeDashTheme(themeValue);
      document.body.setAttribute('data-theme', v);
      if (themeSelect) themeSelect.value = v;
    }
    var topologyNetworkInstance = null;
    var discoverySelectedIps = [];
    function destroyTopology() {
      if (topologyNetworkInstance && typeof topologyNetworkInstance.destroy === 'function') {
        try {
          topologyNetworkInstance.destroy();
        } catch (eTop) {}
        topologyNetworkInstance = null;
      }
    }
    async function refreshTopology() {
      var container = document.getElementById('topology-network');
      if (!container || typeof vis === 'undefined' || typeof vis.DataSet === 'undefined' || typeof vis.Network === 'undefined') {
        return;
      }
      destroyTopology();
      var res = await jsonFetch('/api/topology', 'GET');
      if (!res.ok) return;
      var nodes = new vis.DataSet(
        (res.body.nodes || []).map(function (n) {
          return { id: n.id, label: n.label, group: n.group, title: n.title };
        })
      );
      var edges = new vis.DataSet(
        (res.body.edges || []).map(function (e) {
          return { from: e.from, to: e.to };
        })
      );
      var options = {
        nodes: {
          shape: 'dot',
          size: 22,
          font: { color: '#e2e8f0', size: 12 },
          borderWidth: 2,
          shadow: { enabled: true, color: 'rgba(0,0,0,0.45)', size: 12 },
        },
        groups: {
          Server: { color: { background: '#4f83ff', border: '#1e40af' } },
          Switch: { color: { background: '#22c55e', border: '#166534' } },
          VM: { color: { background: '#a855f7', border: '#6b21a8' } },
          Website: { color: { background: '#f97316', border: '#9a3412' } },
        },
        edges: {
          smooth: { type: 'dynamic' },
          color: { color: 'rgba(148,163,184,0.35)', highlight: '#38bdf8' },
        },
        physics: { stabilization: { iterations: 120 }, barnesHut: { gravitationalConstant: -24000, springLength: 180 } },
        interaction: { hover: true, navigationButtons: true, keyboard: true },
      };
      topologyNetworkInstance = new vis.Network(container, { nodes: nodes, edges: edges }, options);
    }
    async function refreshAuditTrail() {
      var root = document.getElementById('audit-trail-root');
      if (!root) return;
      var res = await jsonFetch('/api/audit-trail', 'GET');
      clearElement(root);
      if (!res.ok || !res.body || !Array.isArray(res.body.entries) || !res.body.entries.length) {
        root.textContent = t('noData');
        return;
      }
      var table = document.createElement('table');
      table.className = 'sentinel-data-table sentinel-alert-table';
      var thead = document.createElement('thead');
      var trh = document.createElement('tr');
      ['auditColTime', 'auditColUser', 'auditColAction'].forEach(function (key) {
        var th = document.createElement('th');
        th.textContent = t(key);
        trh.appendChild(th);
      });
      thead.appendChild(trh);
      table.appendChild(thead);
      var tbody = document.createElement('tbody');
      res.body.entries.forEach(function (row) {
        var tr = document.createElement('tr');
        [row.timestamp, row.username, row.action_description].forEach(function (cell) {
          var td = document.createElement('td');
          td.textContent = cell === undefined || cell === null ? '' : String(cell);
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      root.appendChild(table);
    }
    const discoveryModal = document.getElementById('discovery-modal');
    const discoveryDismiss = document.getElementById('discovery-dismiss');
    const discoveryBackdrop = discoveryModal ? discoveryModal.querySelector('[data-discovery-dismiss]') : null;
    const discoveryRunBtn = document.getElementById('discovery-run-btn');
    const discoveryImportBtn = document.getElementById('discovery-import-btn');
    const discoveryCidrInput = document.getElementById('discovery-cidr-input');
    const discoveryResults = document.getElementById('discovery-results');
    const openDiscoveryBtn = document.getElementById('open-discovery-modal');
    function openDiscoveryModal() {
      if (!discoveryModal) return;
      discoverySelectedIps = [];
      if (discoveryResults) {
        discoveryResults.textContent = '';
      }
      discoveryModal.classList.add('open');
      applyI18nToDom();
    }
    function closeDiscoveryModal() {
      if (!discoveryModal) return;
      discoveryModal.classList.remove('open');
    }
    function syncHashToNav() {
      var h = (location.hash || '').replace(/^#/, '');
      var view = 'home';
      if (h.indexOf('view-') === 0) {
        view = h.slice(5);
      }
      navBtns.forEach(function (b) {
        b.classList.toggle('active', b.getAttribute('data-dashboard-view') === view);
      });
      panels.forEach(function (p) {
        p.classList.toggle('active', p.getAttribute('data-dashboard-panel') === view);
      });
      if (view === 'topology') {
        setTimeout(function () {
          refreshTopology();
        }, 40);
      } else {
        destroyTopology();
      }
      if (view === 'settings') {
        refreshAuditTrail();
      }
    }
    navBtns.forEach(function (b) {
      b.addEventListener('click', function () {
        var v = b.getAttribute('data-dashboard-view');
        location.hash = 'view-' + v;
        syncHashToNav();
      });
    });
    window.addEventListener('hashchange', syncHashToNav);
    window.__activateDashboardView = function (v) {
      location.hash = 'view-' + v;
      syncHashToNav();
    };
    syncHashToNav();
    window.addEventListener('keydown', function (evt) {
      if (evt.key === 'Escape' && discoveryModal && discoveryModal.classList.contains('open')) {
        closeDiscoveryModal();
      }
    });
    var topologyRefreshBtn = document.getElementById('topology-refresh');
    if (topologyRefreshBtn) topologyRefreshBtn.addEventListener('click', refreshTopology);
    if (openDiscoveryBtn) openDiscoveryBtn.addEventListener('click', openDiscoveryModal);
    if (discoveryDismiss) discoveryDismiss.addEventListener('click', closeDiscoveryModal);
    if (discoveryBackdrop) discoveryBackdrop.addEventListener('click', closeDiscoveryModal);
    var auditTrailRefresh = document.getElementById('refresh-audit-trail');
    if (auditTrailRefresh) auditTrailRefresh.addEventListener('click', refreshAuditTrail);
    if (discoveryRunBtn && discoveryCidrInput && discoveryResults) {
      discoveryRunBtn.addEventListener('click', async function () {
        var cidr = String(discoveryCidrInput.value || '').trim();
        if (!cidr) return;
        var dl = document.getElementById('discovery-scan-loading');
        if (dl) dl.classList.add('active');
        discoverySelectedIps = [];
        try {
          var dr = await jsonFetch('/api/discovery/run', 'POST', { cidr: cidr });
          if (!dr.ok) {
            clearElement(discoveryResults);
            var errNode = document.createElement('div');
            errNode.textContent =
              dr.status === 403 ? t('discoveryForbidden') : dr.body && dr.body.detail ? String(dr.body.detail) : t('noData');
            discoveryResults.appendChild(errNode);
            return;
          }
          discoverySelectedIps = dr.body && Array.isArray(dr.body.active_ips) ? dr.body.active_ips.slice() : [];
          clearElement(discoveryResults);
          discoverySelectedIps.forEach(function (ip) {
            var lab = document.createElement('label');
            lab.style.display = 'flex';
            lab.style.gap = '8px';
            lab.style.alignItems = 'center';
            lab.style.marginBottom = '6px';
            var cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.checked = true;
            cb.dataset.ip = ip;
            var span = document.createElement('span');
            span.textContent = ip;
            lab.appendChild(cb);
            lab.appendChild(span);
            discoveryResults.appendChild(lab);
          });
        } finally {
          if (dl) dl.classList.remove('active');
        }
      });
    }
    if (discoveryImportBtn && discoveryResults) {
      discoveryImportBtn.addEventListener('click', async function () {
        var boxes = discoveryResults.querySelectorAll('input[type="checkbox"]');
        var selected = [];
        boxes.forEach(function (bx) {
          if (bx.checked && bx.dataset.ip) selected.push({ ip_address: bx.dataset.ip });
        });
        if (!selected.length) {
          showDevAIToast(t('discoveryNoSelection'), true);
          return;
        }
        var ir = await jsonFetch('/api/discovery/import', 'POST', {
          hosts: selected,
          hostname_prefix: 'edge',
          default_device_type: 'Server',
          default_vendor_template: 'generic_linux_net_snmp',
          default_polling_interval_seconds: 60,
          default_poll_protocol: 'SNMP',
        });
        if (!ir.ok) {
          showDevAIToast(t('discoveryForbidden'), true);
          return;
        }
        showDevAIToast(String((ir.body && ir.body.imported) || 0) + ' hosts', false);
        closeDiscoveryModal();
        if (typeof window.__monitoringRefreshLanguages === 'function') await window.__monitoringRefreshLanguages();
      });
    }
    if (collapseBtn && appShell) {
      collapseBtn.addEventListener('click', function () {
        appShell.classList.toggle('sentinel-sidebar-collapsed');
        if (typeof window.__postDashboardUserSettings === 'function') {
          window.__postDashboardUserSettings();
        }
      });
    }
    window.__postDashboardUserSettings = async function () {
      if (pageName !== 'dashboard') return;
      var payload = {
        default_language: currentLanguage,
        theme_choice: themeSelect ? normalizeDashTheme(themeSelect.value) : 'vibrant_dark',
        sidebar_collapsed: appShell && appShell.classList.contains('sentinel-sidebar-collapsed') ? 1 : 0,
      };
      await jsonFetch('/api/settings', 'POST', payload);
    };
    if (themeSelect) {
      themeSelect.addEventListener('change', function () {
        applyThemeToBody(themeSelect.value);
        window.__postDashboardUserSettings();
      });
    }
    async function pullUserSettings() {
      var r = await jsonFetch('/api/settings', 'GET');
      if (!r.ok) return;
      currentLanguage = normalizeClientLanguage(r.body.default_language);
      if (languageSelect) languageSelect.value = currentLanguage;
      persistLanguage(currentLanguage);
      applyThemeToBody(r.body.theme_choice);
      if (appShell) {
        if (Number(r.body.sidebar_collapsed)) appShell.classList.add('sentinel-sidebar-collapsed');
        else appShell.classList.remove('sentinel-sidebar-collapsed');
      }
      applyI18nToDom();
    }
    async function refreshHomeStats() {
      var root = document.getElementById('home-stats-root');
      if (!root) return;
      var hr = await jsonFetch('/api/hosts', 'GET');
      var mr = await jsonFetch('/api/metrics/latest', 'GET');
      clearElement(root);
      var hosts = hr.ok && hr.body && hr.body.hosts ? hr.body.hosts : [];
      var metrics = mr.ok && mr.body && mr.body.metrics ? mr.body.metrics : [];
      var online = 0;
      metrics.forEach(function (m) {
        if (String(m.status || '').toLowerCase() !== 'offline') online++;
      });
      function statCard(labelKey, valueNum) {
        var wrap = document.createElement('div');
        wrap.className = 'sentinel-home-stat';
        var kEl = document.createElement('div');
        kEl.className = 'sentinel-home-stat-k';
        kEl.textContent = t(labelKey);
        var vEl = document.createElement('div');
        vEl.className = 'sentinel-home-stat-v';
        vEl.textContent = String(valueNum);
        wrap.appendChild(kEl);
        wrap.appendChild(vEl);
        root.appendChild(wrap);
      }
      statCard('homeCardHosts', hosts.length);
      statCard('homeCardOnline', online);
      statCard('homeCardMetrics', metrics.length);
    }
    async function refreshAlertLogs() {
      var root = document.getElementById('alert-logs-root');
      if (!root) return;
      var res = await jsonFetch('/api/alert-logs', 'GET');
      clearElement(root);
      if (!res.ok || !res.body || !Array.isArray(res.body.logs) || !res.body.logs.length) {
        root.textContent = t('noData');
        return;
      }
      var table = document.createElement('table');
      table.className = 'sentinel-data-table sentinel-alert-table';
      var thead = document.createElement('thead');
      var trh = document.createElement('tr');
      ['alertColTime', 'alertColHost', 'alertColType', 'alertColStatus', 'alertColMessage'].forEach(function (key) {
        var th = document.createElement('th');
        th.textContent = t(key);
        trh.appendChild(th);
      });
      thead.appendChild(trh);
      table.appendChild(thead);
      var tbody = document.createElement('tbody');
      res.body.logs.forEach(function (row) {
        var tr = document.createElement('tr');
        [row.timestamp, row.host_id === null || row.host_id === undefined ? '—' : String(row.host_id), row.alert_type, row.delivery_status, row.message_text].forEach(function (cell) {
          var td = document.createElement('td');
          td.textContent = cell === undefined || cell === null ? '' : String(cell);
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      root.appendChild(table);
    }
    async function loadSystemTelegramFields() {
      var res = await jsonFetch('/api/system-settings', 'GET');
      if (!res.ok) return;
      var tok = document.getElementById('system-telegram-token');
      var chat = document.getElementById('system-telegram-chat');
      if (tok) tok.value = String(res.body.telegram_bot_token || '');
      if (chat) chat.value = String(res.body.telegram_chat_id || '');
    }
    async function refreshProfile() {
      var res = await jsonFetch('/api/me', 'GET');
      if (!res.ok) return;
      var u = document.getElementById('profile-username');
      var r = document.getElementById('profile-role');
      if (u) u.textContent = String(res.body.username || '');
      if (r) r.textContent = String(res.body.role || '');
      window.__devaiRole = String(res.body.role || '');
    }
    if (alertRefresh) alertRefresh.addEventListener('click', refreshAlertLogs);
    if (profileForm) {
      profileForm.addEventListener('submit', async function (ev) {
        ev.preventDefault();
        var cur = document.getElementById('profile-current-password');
        var nw = document.getElementById('profile-new-password');
        var cf = document.getElementById('profile-confirm-password');
        var st = document.getElementById('profile-password-status');
        if (!cur || !nw || !cf) return;
        if (String(nw.value) !== String(cf.value)) {
          if (st) st.textContent = t('profilePasswordMismatch');
          return;
        }
        var pr = await jsonFetch('/api/profile/password', 'POST', {
          current_password: String(cur.value || ''),
          new_password: String(nw.value || ''),
        });
        if (st) st.textContent = pr.ok ? t('profilePasswordOk') : t('profilePasswordFail');
        if (pr.ok) profileForm.reset();
      });
    }
    if (systemSave) {
      systemSave.addEventListener('click', async function () {
        var tok = document.getElementById('system-telegram-token');
        var chat = document.getElementById('system-telegram-chat');
        var res = await jsonFetch('/api/system-settings', 'POST', {
          telegram_bot_token: tok ? String(tok.value || '') : '',
          telegram_chat_id: chat ? String(chat.value || '') : '',
        });
        if (systemStatus) {
          if (res.ok) systemStatus.textContent = t('settingsTelegramSaved');
          else if (res.status === 403) systemStatus.textContent = t('settingsTelegramForbidden');
          else systemStatus.textContent = t('profilePasswordFail');
        }
      });
    }
    await pullUserSettings();
    await refreshHomeStats();
    await loadSystemTelegramFields();
    await refreshProfile();
    if (openDiscoveryBtn) openDiscoveryBtn.style.display = window.__devaiRole === 'Admin' ? '' : 'none';
    await refreshAlertLogs();
    sentinelMonitoringCore();
    var previousRefresh = window.__monitoringRefreshLanguages;
    window.__monitoringRefreshLanguages = async function () {
      if (typeof previousRefresh === 'function') await previousRefresh();
      await refreshHomeStats();
      await refreshAlertLogs();
    };
  }

  if (pageName === 'audit') auditWireup();
  if (pageName === 'monitoring') sentinelMonitoringCore();
  if (pageName === 'dashboard') {
    auditWireup();
    void dashboardWireup();
  }
})();
