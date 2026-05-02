(function () {
  const UI_STRINGS = {
    en: {
      documentMonitoringTitle: 'Infrastructure Sentinel — Vigil Console',
      landingDocTitle: 'Infrastructure Sentinel',
      auditDocTitle: 'Infrastructure Sentinel — Audit Forge',
      brandTitle: 'Infrastructure Sentinel',
      monitoringSubtitle: 'Localized auditing fabric with multilingual insights',
      landingAuditTitle: 'Network Audit',
      landingAuditSubtitle: 'Run adaptive scanning with noise-aware AI remediation workflows',
      landingMonitoringTitle: 'Infrastructure Sentinel Console',
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
      legendOnline: 'Online',
      legendIssue: 'Attention',
    },
    ru: {
      documentMonitoringTitle: 'Infrastructure Sentinel — консоль наблюдения',
      landingDocTitle: 'Infrastructure Sentinel',
      auditDocTitle: 'Infrastructure Sentinel — кузница аудита',
      brandTitle: 'Infrastructure Sentinel',
      monitoringSubtitle: 'Локализованная аудиторская ткань с многоязычным интеллектом',
      landingAuditTitle: 'Сетевой аудит',
      landingAuditSubtitle: 'Адаптивное сканирование с ИИ-устранением и подавлением шума',
      landingMonitoringTitle: 'Консоль Infrastructure Sentinel',
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
      legendOnline: 'Онлайн',
      legendIssue: 'Внимание',
    },
    hy: {
      documentMonitoringTitle: 'Infrastructure Sentinel — դիտարկման կոնսոլ',
      landingDocTitle: 'Infrastructure Sentinel',
      auditDocTitle: 'Infrastructure Sentinel — աուդիտի կայան',
      brandTitle: 'Infrastructure Sentinel',
      monitoringSubtitle: 'Տեղայնացված աուդիտի հարթակ բազմալեզու վերլուծությամբ',
      landingAuditTitle: 'Ցանցային աուդիտ',
      landingAuditSubtitle: 'Ճկուն սկանավորում՝ աղմուկի նվազեցմամբ և AI վերականգնմամբ',
      landingMonitoringTitle: 'Infrastructure Sentinel կոնսոլ',
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
      legendOnline: 'Առցանց',
      legendIssue: 'Ուշադրություն',
    },
  };

  const STORAGE_KEY = 'audit_ui_lang';
  let currentLanguage = 'en';

  const languageSelect = document.getElementById('language-select');
  const pageName = document.body ? document.body.getAttribute('data-page') : '';

  window.__monitoringRefreshLanguages = window.__monitoringRefreshLanguages || null;

  function t(key) {
    const pack = UI_STRINGS[currentLanguage] || UI_STRINGS.en;
    return Object.prototype.hasOwnProperty.call(pack, key) ? pack[key] : UI_STRINGS.en[key] || key;
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
    const docTitleNode = document.querySelector('title[data-i18n]');
    if (docTitleNode) {
      const dt = docTitleNode.getAttribute('data-i18n');
      if (dt) docTitleNode.textContent = t(dt);
    } else if (pageName === 'landing') {
      document.title = t('landingDocTitle');
    } else if (pageName === 'audit') {
      document.title = t('auditDocTitle');
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
    });
  }

  async function jsonFetch(url, method, payload) {
    const res = await fetch(url, {
      method: method || 'GET',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: payload ? JSON.stringify(payload) : undefined,
    });
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
          if (!advisories.length) {
            vulnRoot.textContent = t('noData');
          } else {
            advisories.forEach(function (item) {
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
        runBtn.disabled = false;
      }
    });
  }

  function monitoringWireup() {
    const navButtons = document.querySelectorAll('.nav-btn');
    const viewHosts = document.getElementById('view-hosts');
    const viewLive = document.getElementById('view-live');
    const viewAi = document.getElementById('view-ai');
    const hostsBody = document.getElementById('hosts-table-body');
    const liveRoot = document.getElementById('live-dashboard-root');
    const aiRoot = document.getElementById('ai-decisions');
    const refreshHosts = document.getElementById('refresh-hosts');
    const createHost = document.getElementById('create-host');
    const updateHost = document.getElementById('update-host');
    const clearHost = document.getElementById('clear-host');
    const pollBtn = document.getElementById('poll-metrics');
    const refreshMetrics = document.getElementById('refresh-metrics');
    const refreshAi = document.getElementById('refresh-ai');
    const hostIdEl = document.getElementById('host-id');
    const hostNameEl = document.getElementById('host-hostname');
    const hostIpEl = document.getElementById('host-ip');
    const hostTypeEl = document.getElementById('host-device-type');
    const tempHeading = document.getElementById('hosts-temperature-heading');
    const modal = document.getElementById('host-metrics-modal');
    const modalDismiss = document.getElementById('host-modal-dismiss');
    const modalBackdrop = modal ? modal.querySelector('[data-dismiss-modal]') : null;
    const modalHeading = document.getElementById('host-modal-heading');
    const metricScope = document.getElementById('host-metric-scope');
    const metricStart = document.getElementById('host-metric-start');
    const metricEnd = document.getElementById('host-metric-end');
    const metricRefresh = document.getElementById('host-metric-refresh');
    let chartInstance = null;
    let activeHostContext = null;

    function showView(name) {
      [viewHosts, viewLive, viewAi].forEach(function (v) {
        if (v) v.classList.remove('active');
      });
      if (name === 'hosts' && viewHosts) viewHosts.classList.add('active');
      if (name === 'live' && viewLive) viewLive.classList.add('active');
      if (name === 'ai' && viewAi) viewAi.classList.add('active');
      navButtons.forEach(function (b) {
        b.classList.toggle('active', b.getAttribute('data-view') === name);
      });
    }

    navButtons.forEach(function (b) {
      b.addEventListener('click', function () {
        showView(b.getAttribute('data-view'));
      });
    });

    function fillHostForm(host) {
      if (hostIdEl) hostIdEl.value = String(host.id || '');
      if (hostNameEl) hostNameEl.value = String(host.hostname || '');
      if (hostIpEl) hostIpEl.value = String(host.ip_address || '');
      if (hostTypeEl) hostTypeEl.value = String(host.device_type || 'Server');
    }

    function clearHostForm() {
      if (hostIdEl) hostIdEl.value = '';
      if (hostNameEl) hostNameEl.value = '';
      if (hostIpEl) hostIpEl.value = '';
      if (hostTypeEl) hostTypeEl.value = 'Server';
    }

    function statusClass(statusValue) {
      return String(statusValue).toLowerCase() === 'offline' ? 'warn' : 'good';
    }

    function buildMetricRow(label, numericValue, tone) {
      const row = document.createElement('div');
      row.className = 'sentinel-metric-chip ' + (tone || 'good');
      const left = document.createElement('span');
      left.textContent = label;
      const right = document.createElement('span');
      right.dataset.metricValue = '1';
      right.textContent = String(numericValue);
      row.appendChild(left);
      row.appendChild(right);
      return row;
    }

    function groupBuckets(rows) {
      const servers = [];
      const switches = [];
      const vms = [];
      rows.forEach(function (row) {
        const kind = String(row.device_type || '');
        if (kind === 'Switch') switches.push(row);
        else if (kind === 'VM') vms.push(row);
        else servers.push(row);
      });
      return { servers: servers, switches: switches, vms: vms };
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
        const dot = document.createElement('span');
        dot.className = 'sentinel-pulse-dot ' + (statusClass(metricRow.status) === 'warn' ? 'sentinel-pulse-offline' : 'sentinel-pulse-online');
        const statusCaption = document.createElement('span');
        statusCaption.textContent = String(metricRow.status || 'unknown');
        statusRow.appendChild(dot);
        statusRow.appendChild(statusCaption);
        const metricWrap = document.createElement('div');
        metricWrap.className = 'sentinel-metric-rows';
        metricWrap.appendChild(buildMetricRow(t('cpu'), metricRow.cpu_utilization || 0, statusClass(metricRow.status)));
        metricWrap.appendChild(buildMetricRow(t('ram'), metricRow.ram_usage || 0, 'good'));
        metricWrap.appendChild(buildMetricRow(t('disk'), metricRow.disk_usage || 0, (metricRow.disk_usage || 0) > 90 ? 'warn' : 'good'));
        if (String(metricRow.device_type) !== 'VM') {
          const temperatureReading = metricRow.temperature_c === null || metricRow.temperature_c === undefined ? '' : String(metricRow.temperature_c);
          metricWrap.appendChild(buildMetricRow(t('temp'), temperatureReading, 'good'));
        }
        const polled = document.createElement('div');
        polled.style.marginTop = '10px';
        polled.style.fontSize = '0.75rem';
        polled.style.color = 'var(--text-muted)';
        polled.textContent = t('polledAt') + ': ' + String(metricRow.polled_at || '');
        card.appendChild(metaRow);
        card.appendChild(statusRow);
        card.appendChild(metricWrap);
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
      const buckets = [[ 'heatClusterServers', 'sentinel-cluster-servers', groups.servers ], [ 'heatClusterSwitches', 'sentinel-cluster-switches', groups.switches ], [ 'heatClusterVms', 'sentinel-cluster-vms', groups.vms ]];
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
      const res = await jsonFetch('/api/hosts', 'GET');
      if (!res.ok) return;
      const packMetrics = await jsonFetch('/api/metrics/latest', 'GET');
      clearElement(hostsBody);
      const hosts = res.body && Array.isArray(res.body.hosts) ? res.body.hosts : [];
      const metricsRows = packMetrics.ok && packMetrics.body && Array.isArray(packMetrics.body.metrics) ? packMetrics.body.metrics : [];
      const telemetryIndex = {};
      metricsRows.forEach(function (snapshot) {
        telemetryIndex[String(snapshot.host_id)] = snapshot;
      });
      const hasThermal = hosts.some(function (candidate) {
        return String(candidate.device_type || '') !== 'VM';
      });
      if (tempHeading) {
        tempHeading.style.display = hasThermal ? '' : 'none';
      }
      hosts.forEach(function (hostRow) {
        const tr = document.createElement('tr');
        ;[hostRow.id, hostRow.hostname, hostRow.ip_address, hostRow.device_type].forEach(function (columnValue) {
          const td = document.createElement('td');
          td.textContent = columnValue === undefined || columnValue === null ? '' : String(columnValue);
          tr.appendChild(td);
        });
        if (hasThermal) {
          const thermalCell = document.createElement('td');
          if (String(hostRow.device_type) === 'VM') {
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
          fillHostForm(hostRow);
          showView('hosts');
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

    async function createHostAction() {
      const payload = {
        hostname: hostNameEl ? String(hostNameEl.value || '').trim() : '',
        ip_address: hostIpEl ? String(hostIpEl.value || '').trim() : '',
        device_type: hostTypeEl ? hostTypeEl.value : 'Server',
      };
      const res = await jsonFetch('/api/hosts', 'POST', payload);
      if (res.ok) {
        clearHostForm();
        await loadHosts();
      } else {
        alert('Request failed');
      }
    }

    async function updateHostAction() {
      const payload = {
        id: hostIdEl ? Number(hostIdEl.value || 0) : 0,
        hostname: hostNameEl ? String(hostNameEl.value || '').trim() : '',
        ip_address: hostIpEl ? String(hostIpEl.value || '').trim() : '',
        device_type: hostTypeEl ? hostTypeEl.value : 'Server',
      };
      const res = await jsonFetch('/api/hosts', 'PUT', payload);
      if (res.ok) {
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
      const resPoll = await jsonFetch('/api/metrics/poll', 'POST', {});
      if (!resPoll.ok) return;
      await loadMetricsLatest();
    }

    async function loadAiDecisions() {
      const res = await jsonFetch('/api/ai/decisions', 'POST', { language: currentLanguage });
      if (!res.ok) return;
      clearElement(aiRoot);
      const decisions = res.body && Array.isArray(res.body.decisions) ? res.body.decisions : [];
      if (decisions.length === 0) {
        aiRoot.textContent = t('noData');
        return;
      }
      decisions.forEach(function (d) {
        const panel = document.createElement('article');
        panel.className = 'sentinel-ai-card sentinel-fade-up';
        const h = document.createElement('h3');
        h.textContent = String(d.hostname || '') + ' (' + String(d.ip_address || '') + ') • ' + String(d.title || '');
        const narrative = document.createElement('div');
        narrative.className = 'sentinel-ai-block';
        narrative.textContent = String(d.trend_analysis || '');
        const pre = document.createElement('pre');
        pre.className = 'sentinel-code-slab';
        const code = document.createElement('code');
        code.textContent = String(d.script || '');
        pre.appendChild(code);
        panel.appendChild(h);
        panel.appendChild(narrative);
        if (String(d.resolution_text || '').trim()) {
          const playbook = document.createElement('div');
          playbook.className = 'sentinel-ai-block';
          playbook.style.color = '#e2e8f0';
          playbook.textContent = String(d.resolution_text || '');
          panel.appendChild(playbook);
        }
        panel.appendChild(pre);
        aiRoot.appendChild(panel);
      });
    }

    window.__monitoringRefreshLanguages = async function () {
      await loadHosts();
      await loadMetricsLatest();
      await loadAiDecisions();
      applyI18nToDom();
      await loadHistorySeries().catch(function () {});
    };

    if (refreshHosts) refreshHosts.addEventListener('click', loadHosts);
    if (createHost) createHost.addEventListener('click', createHostAction);
    if (updateHost) updateHost.addEventListener('click', updateHostAction);
    if (clearHost) clearHost.addEventListener('click', clearHostForm);
    if (pollBtn) pollBtn.addEventListener('click', pollMetrics);
    if (refreshMetrics) refreshMetrics.addEventListener('click', loadMetricsLatest);
    if (refreshAi) refreshAi.addEventListener('click', loadAiDecisions);
    if (metricRefresh) metricRefresh.addEventListener('click', loadHistorySeries);
    if (metricScope) metricScope.addEventListener('change', loadHistorySeries);
    if (modalDismiss) modalDismiss.addEventListener('click', closeModalSurface);
    if (modalBackdrop) modalBackdrop.addEventListener('click', closeModalSurface);
    window.addEventListener('keydown', function (evt) {
      if (evt.key === 'Escape') closeModalSurface();
    });

    loadHosts();
    loadMetricsLatest();
    loadAiDecisions();
  }

  if (pageName === 'audit') auditWireup();
  if (pageName === 'monitoring') monitoringWireup();
})();
