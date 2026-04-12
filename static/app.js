(function () {
  const UI_STRINGS = {
    en: {
      brandTitle: 'Infrastructure Observability',
      brandSubtitle: 'Local System Audit Intelligence',
      languageLabel: 'Language',
      subnetPlaceholder: 'Enter Subnet (e.g., 192.168.1.0/24) - Optional',
      runAudit: 'Run Network Audit',
      loadingMessage: 'Running network audit pipeline',
      loadingAria: 'Running audit',
      statusOverview: 'Status Overview',
      statActiveIps: 'Active IPs',
      statOpenPorts: 'Open Ports',
      statOutdatedPackages: 'Outdated Packages',
      statHintBind: 'Unique bind addresses',
      statHintSockets: 'Listening sockets',
      statHintPip: 'Python pip report',
      networkAssets: 'Discovered Network Assets',
      colIp: 'IP Address',
      colPort: 'Port',
      colProtocol: 'Protocol',
      colService: 'Guessed Service',
      colProcess: 'Process',
      aiRemediation: 'AI Remediation Plan',
      footerNote: 'Powered by local TF-IDF similarity matching against sysadmin_knowledge.db',
      lastRunPrefix: 'Last run:',
      aiConfidence: 'AI Confidence',
      remediationFallbackTitle: 'Remediation item',
      emptySocketsMessage: 'No listening sockets were returned by the scanner.',
      emptyRemediationMessage: 'No remediation matches were produced.',
      endpointsCount: '{n} endpoints',
      recommendationsCount: '{n} recommendations',
      errorInvalidJson: 'The server returned data that is not valid JSON.',
      errorUnexpectedEmpty: 'Unexpected empty response from audit service.',
      errorNetwork: 'Network error while contacting the audit API.',
    },
    ru: {
      brandTitle: 'Наблюдаемость инфраструктуры',
      brandSubtitle: 'Локальный интеллект аудита системы',
      languageLabel: 'Язык',
      subnetPlaceholder: 'Подсеть (например, 192.168.1.0/24) — необязательно',
      runAudit: 'Запустить сетевой аудит',
      loadingMessage: 'Выполняется конвейер сетевого аудита',
      loadingAria: 'Выполняется аудит',
      statusOverview: 'Обзор состояния',
      statActiveIps: 'Активные IP',
      statOpenPorts: 'Открытые порты',
      statOutdatedPackages: 'Устаревшие пакеты',
      statHintBind: 'Уникальные адреса привязки',
      statHintSockets: 'Прослушивающие сокеты',
      statHintPip: 'Отчёт pip (Python)',
      networkAssets: 'Обнаруженные сетевые активы',
      colIp: 'IP-адрес',
      colPort: 'Порт',
      colProtocol: 'Протокол',
      colService: 'Предполагаемый сервис',
      colProcess: 'Процесс',
      aiRemediation: 'План ИИ-устранения',
      footerNote: 'На основе локального сопоставления TF-IDF с sysadmin_knowledge.db',
      lastRunPrefix: 'Последний запуск:',
      aiConfidence: 'Уверенность ИИ',
      remediationFallbackTitle: 'Элемент устранения',
      emptySocketsMessage: 'Сканер не вернул прослушивающие сокеты.',
      emptyRemediationMessage: 'Рекомендации по устранению не сформированы.',
      endpointsCount: '{n} конечных точек',
      recommendationsCount: '{n} рекомендаций',
      errorInvalidJson: 'Сервер вернул данные, которые не являются допустимым JSON.',
      errorUnexpectedEmpty: 'Пустой или неожиданный ответ службы аудита.',
      errorNetwork: 'Сетевая ошибка при обращении к API аудита.',
    },
    hy: {
      brandTitle: 'Ենթակառուցվածքի դիտարկում',
      brandSubtitle: 'Տեղական համակարգի աուդիտի հետախուզություն',
      languageLabel: 'Լեզու',
      subnetPlaceholder: 'Ենթացանց (օր․ 192.168.1.0/24) — ընտրովի',
      runAudit: 'Գործարկել ցանցային աուդիտ',
      loadingMessage: 'Կատարվում է ցանցային աուդիտի խողովակ',
      loadingAria: 'Կատարվում է աուդիտ',
      statusOverview: 'Կարգավիճակի ամփոփում',
      statActiveIps: 'Ակտիվ IP-ներ',
      statOpenPorts: 'Բաց պորտեր',
      statOutdatedPackages: 'Հնացած փաթեթներ',
      statHintBind: 'Եզակի կապման հասցեներ',
      statHintSockets: 'Լսող սոկետներ',
      statHintPip: 'Python pip հաշվետվություն',
      networkAssets: 'Հայտնաբերված ցանցային ակտիվներ',
      colIp: 'IP հասցե',
      colPort: 'Պորտ',
      colProtocol: 'Պրոտոկոլ',
      colService: 'Գուշակված ծառայություն',
      colProcess: 'Գործընթաց',
      aiRemediation: 'ՁԻ վերականգնման պլան',
      footerNote: 'Տեղական TF-IDF նմանության համապատասխանություն sysadmin_knowledge.db-ի հետ',
      lastRunPrefix: 'Վերջին գործարկումը՝',
      aiConfidence: 'ՁԻ վստահություն',
      remediationFallbackTitle: 'Վերականգնման տարր',
      emptySocketsMessage: 'Սկաները չի վերադարձրել լսող սոկետներ։',
      emptyRemediationMessage: 'Վերականգնման համընկնումներ չեն ստացվել։',
      endpointsCount: '{n} կետ',
      recommendationsCount: '{n} առաջարկ',
      errorInvalidJson: 'Սերվերը վերադարձրեց JSON չհանդիսացող տվյալներ։',
      errorUnexpectedEmpty: 'Աուդիտի ծառայությունից անսպասելի դատարկ պատասխան։',
      errorNetwork: 'Ցանցային սխալ API-ին դիմելիս։',
    },
  };

  const STORAGE_KEY = 'audit_ui_lang';
  let currentLanguage = 'en';

  const runAuditButton = document.getElementById('run-audit-button');
  const subnetInput = document.getElementById('subnet-input');
  const languageSelect = document.getElementById('language-select');
  const loadingOverlay = document.getElementById('loading-overlay');
  const statActiveIps = document.getElementById('stat-active-ips');
  const statOpenPorts = document.getElementById('stat-open-ports');
  const statOutdatedPackages = document.getElementById('stat-outdated-packages');
  const auditTimestamp = document.getElementById('audit-timestamp');
  const assetsTableBody = document.getElementById('assets-table-body');
  const assetRowCount = document.getElementById('asset-row-count');
  const remediationGrid = document.getElementById('remediation-grid');
  const remediationCount = document.getElementById('remediation-count');
  const errorBanner = document.getElementById('error-banner');

  function getLocaleTag() {
    if (currentLanguage === 'ru') {
      return 'ru-RU';
    }
    if (currentLanguage === 'hy') {
      return 'hy-AM';
    }
    return 'en-US';
  }

  function t(key) {
    const pack = UI_STRINGS[currentLanguage] || UI_STRINGS.en;
    if (Object.prototype.hasOwnProperty.call(pack, key)) {
      return pack[key];
    }
    return UI_STRINGS.en[key] || key;
  }

  function formatNamed(template, n) {
    return String(template).replace('{n}', String(n));
  }

  function applyI18nToDom() {
    const htmlLang = currentLanguage === 'hy' ? 'hy' : currentLanguage === 'ru' ? 'ru' : 'en';
    document.documentElement.setAttribute('lang', htmlLang);
    document.querySelectorAll('[data-i18n]').forEach(function (el) {
      const key = el.getAttribute('data-i18n');
      if (!key) {
        return;
      }
      el.textContent = t(key);
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) {
      const key = el.getAttribute('data-i18n-placeholder');
      if (!key) {
        return;
      }
      el.placeholder = t(key);
    });
    document.querySelectorAll('[data-i18n-aria-label]').forEach(function (el) {
      const key = el.getAttribute('data-i18n-aria-label');
      if (!key) {
        return;
      }
      el.setAttribute('aria-label', t(key));
    });
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
  if (languageSelect) {
    languageSelect.value = currentLanguage;
  }
  applyI18nToDom();

  if (languageSelect) {
    languageSelect.addEventListener('change', function () {
      currentLanguage = languageSelect.value;
      persistLanguage(currentLanguage);
      applyI18nToDom();
    });
  }

  function getRequestLanguage() {
    return currentLanguage === 'ru' || currentLanguage === 'hy' ? currentLanguage : 'en';
  }

  function setLoadingState(isLoading) {
    if (isLoading) {
      loadingOverlay.classList.remove('hidden');
      loadingOverlay.setAttribute('aria-hidden', 'false');
      runAuditButton.disabled = true;
      if (subnetInput) {
        subnetInput.disabled = true;
      }
      if (languageSelect) {
        languageSelect.disabled = true;
      }
    } else {
      loadingOverlay.classList.add('hidden');
      loadingOverlay.setAttribute('aria-hidden', 'true');
      runAuditButton.disabled = false;
      if (subnetInput) {
        subnetInput.disabled = false;
      }
      if (languageSelect) {
        languageSelect.disabled = false;
      }
    }
  }

  function hideError() {
    errorBanner.classList.add('hidden');
    errorBanner.textContent = '';
  }

  function showError(messageText) {
    errorBanner.textContent = messageText;
    errorBanner.classList.remove('hidden');
  }

  function countUniqueIps(socketRows) {
    const uniqueValues = new Set();
    socketRows.forEach(function (row) {
      if (row && Object.prototype.hasOwnProperty.call(row, 'ip')) {
        uniqueValues.add(String(row.ip));
      }
    });
    return uniqueValues.size;
  }

  function formatConfidencePercent(similarityScore) {
    const numericValue = Number(similarityScore);
    if (!Number.isFinite(numericValue)) {
      return '0%';
    }
    const scaled = Math.round(numericValue * 1000) / 10;
    return String(scaled) + '%';
  }

  function renderOverview(socketRows, outdatedPackagesList) {
    const openPortCount = Array.isArray(socketRows) ? socketRows.length : 0;
    const activeIpCount = Array.isArray(socketRows) ? countUniqueIps(socketRows) : 0;
    const outdatedCount = Array.isArray(outdatedPackagesList) ? outdatedPackagesList.length : 0;
    statActiveIps.textContent = String(activeIpCount);
    statOpenPorts.textContent = String(openPortCount);
    statOutdatedPackages.textContent = String(outdatedCount);
    const instant = new Date();
    auditTimestamp.textContent = t('lastRunPrefix') + ' ' + instant.toLocaleString(getLocaleTag());
  }

  function clearTableBody() {
    while (assetsTableBody.firstChild) {
      assetsTableBody.removeChild(assetsTableBody.firstChild);
    }
  }

  function appendAssetRow(socketRow) {
    const tableRow = document.createElement('tr');
    const ipCell = document.createElement('td');
    const portCell = document.createElement('td');
    const protocolCell = document.createElement('td');
    const serviceCell = document.createElement('td');
    const processCell = document.createElement('td');
    ipCell.textContent = socketRow && socketRow.ip !== undefined ? String(socketRow.ip) : '';
    portCell.textContent = socketRow && socketRow.port !== undefined ? String(socketRow.port) : '';
    protocolCell.textContent = socketRow && socketRow.protocol !== undefined ? String(socketRow.protocol) : '';
    serviceCell.textContent = socketRow && socketRow.service_guess !== undefined ? String(socketRow.service_guess) : '';
    processCell.textContent = socketRow && socketRow.process_name !== undefined ? String(socketRow.process_name) : '';
    tableRow.appendChild(ipCell);
    tableRow.appendChild(portCell);
    tableRow.appendChild(protocolCell);
    tableRow.appendChild(serviceCell);
    tableRow.appendChild(processCell);
    assetsTableBody.appendChild(tableRow);
  }

  function renderAssetsTable(socketRows) {
    clearTableBody();
    if (!Array.isArray(socketRows) || socketRows.length === 0) {
      assetRowCount.textContent = formatNamed(t('endpointsCount'), 0);
      const emptyRow = document.createElement('tr');
      const emptyCell = document.createElement('td');
      emptyCell.colSpan = 5;
      emptyCell.textContent = t('emptySocketsMessage');
      emptyCell.style.color = '#94a3b8';
      emptyCell.style.fontStyle = 'italic';
      emptyRow.appendChild(emptyCell);
      assetsTableBody.appendChild(emptyRow);
      return;
    }
    assetRowCount.textContent = formatNamed(t('endpointsCount'), socketRows.length);
    socketRows.forEach(function (socketRow) {
      appendAssetRow(socketRow);
    });
  }

  function clearRemediationGrid() {
    while (remediationGrid.firstChild) {
      remediationGrid.removeChild(remediationGrid.firstChild);
    }
  }

  function appendRemediationCard(planItem) {
    const cardElement = document.createElement('article');
    cardElement.className = 'remediation-card';
    const headerElement = document.createElement('div');
    headerElement.className = 'remediation-card-header';
    const titleElement = document.createElement('h3');
    titleElement.className = 'remediation-title';
    titleElement.textContent = planItem && planItem.title ? String(planItem.title) : t('remediationFallbackTitle');
    const pillElement = document.createElement('div');
    pillElement.className = 'confidence-pill';
    const labelElement = document.createElement('span');
    labelElement.className = 'confidence-label';
    labelElement.textContent = t('aiConfidence');
    const valueElement = document.createElement('strong');
    valueElement.textContent = formatConfidencePercent(planItem ? planItem.similarity_score : 0);
    pillElement.appendChild(labelElement);
    pillElement.appendChild(valueElement);
    headerElement.appendChild(titleElement);
    headerElement.appendChild(pillElement);
    const bodyElement = document.createElement('div');
    bodyElement.className = 'remediation-body';
    bodyElement.textContent = planItem && planItem.resolution_steps ? String(planItem.resolution_steps) : '';
    cardElement.appendChild(headerElement);
    cardElement.appendChild(bodyElement);
    remediationGrid.appendChild(cardElement);
  }

  function renderRemediationPlan(planItems) {
    clearRemediationGrid();
    if (!Array.isArray(planItems) || planItems.length === 0) {
      remediationCount.textContent = formatNamed(t('recommendationsCount'), 0);
      const emptyState = document.createElement('div');
      emptyState.className = 'muted-chip';
      emptyState.style.display = 'inline-block';
      emptyState.style.marginTop = '6px';
      emptyState.textContent = t('emptyRemediationMessage');
      remediationGrid.appendChild(emptyState);
      return;
    }
    remediationCount.textContent = formatNamed(t('recommendationsCount'), planItems.length);
    planItems.forEach(function (planItem) {
      appendRemediationCard(planItem);
    });
  }

  function renderDashboardFromPayload(payloadObject) {
    const scannerResults = payloadObject && payloadObject.scanner_results ? payloadObject.scanner_results : {};
    const socketRows = scannerResults.listening_sockets;
    const outdatedReport = scannerResults.python_package_outdated_report || {};
    const outdatedPackagesList = outdatedReport.packages || [];
    const remediationPlan = payloadObject && payloadObject.remediation_plan ? payloadObject.remediation_plan : [];
    renderOverview(socketRows, outdatedPackagesList);
    renderAssetsTable(socketRows);
    renderRemediationPlan(remediationPlan);
  }

  async function handleRunAuditClick() {
    hideError();
    setLoadingState(true);
    try {
      const trimmedSubnetValue = subnetInput ? String(subnetInput.value).trim() : '';
      const requestPayload = {
        language: getRequestLanguage(),
      };
      if (trimmedSubnetValue.length > 0) {
        requestPayload.subnet = trimmedSubnetValue;
      }
      const requestBodyString = JSON.stringify(requestPayload);
      const response = await fetch('/api/run_audit', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: requestBodyString,
      });
      const responseText = await response.text();
      let parsedBody = null;
      try {
        parsedBody = responseText ? JSON.parse(responseText) : null;
      } catch (parseError) {
        showError(t('errorInvalidJson'));
        return;
      }
      if (!response.ok) {
        const errorLabel = parsedBody && parsedBody.error ? String(parsedBody.error) : 'request_failed';
        const detailParts = [];
        detailParts.push('Status ' + String(response.status) + ' (' + errorLabel + ')');
        if (parsedBody && parsedBody.stderr_excerpt) {
          detailParts.push(String(parsedBody.stderr_excerpt));
        }
        if (parsedBody && parsedBody.stdout_excerpt) {
          detailParts.push(String(parsedBody.stdout_excerpt));
        }
        showError(detailParts.join('\n\n'));
        return;
      }
      if (!parsedBody || typeof parsedBody !== 'object') {
        showError(t('errorUnexpectedEmpty'));
        return;
      }
      renderDashboardFromPayload(parsedBody);
    } catch (networkError) {
      showError(t('errorNetwork'));
    } finally {
      setLoadingState(false);
    }
  }

  runAuditButton.addEventListener('click', function () {
    handleRunAuditClick();
  });
})();
