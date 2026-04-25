(function () {
  const UI_STRINGS = {
    en: {
      landingAuditTitle: 'Network Audit',
      landingAuditSubtitle: 'Run smart scanning with noise reduction and AI remediation',
      landingMonitoringTitle: 'Infrastructure Monitoring',
      landingMonitoringSubtitle: 'Zabbix-style observability with hosts, live metrics, and AI decisions',
      backToLanding: 'Back',
      runAudit: 'Run Audit',
      auditTitle: 'Network Audit',
      auditHint: 'Safe whitelist ports are ignored by default; only anomalies are listed.',
      anomalousPorts: 'Anomalous Open Ports',
      rawPayload: 'Raw Payload',
      aiRemediation: 'AI Remediation Plan',
      monitoringTitle: 'Infrastructure Monitoring',
      monitoringSidebarHint: 'Add hosts, poll metrics, then review AI trend decisions.',
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
      noData: 'No data'
    },
    ru: {
      landingAuditTitle: 'Сетевой аудит',
      landingAuditSubtitle: 'Умное сканирование с подавлением шума и ИИ-устранением',
      landingMonitoringTitle: 'Мониторинг инфраструктуры',
      landingMonitoringSubtitle: 'Наблюдаемость в стиле Zabbix: хосты, метрики, решения ИИ',
      backToLanding: 'Назад',
      runAudit: 'Запустить аудит',
      auditTitle: 'Сетевой аудит',
      auditHint: 'Безопасные порты из белого списка скрываются; отображаются только аномалии.',
      anomalousPorts: 'Аномальные открытые порты',
      rawPayload: 'Сырой ответ',
      aiRemediation: 'План ИИ-устранения',
      monitoringTitle: 'Мониторинг инфраструктуры',
      monitoringSidebarHint: 'Добавьте хосты, опросите метрики, затем проверьте трендовые решения ИИ.',
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
      noData: 'Нет данных'
    },
    hy: {
      landingAuditTitle: 'Ցանցային աուդիտ',
      landingAuditSubtitle: 'Խելացի սկանավորում՝ աղմուկի նվազեցմամբ և AI վերականգնմամբ',
      landingMonitoringTitle: 'Ենթակառուցվածքի մոնիտորինգ',
      landingMonitoringSubtitle: 'Zabbix ոճի դիտարկում՝ հոսթեր, մետրիկներ, AI որոշումներ',
      backToLanding: 'Հետ',
      runAudit: 'Գործարկել աուդիտ',
      auditTitle: 'Ցանցային աուդիտ',
      auditHint: 'Անվտանգ պորտերը թաքցվում են լռելյայն, ցուցադրվում են միայն անոմալիաները։',
      anomalousPorts: 'Անոմալ բաց պորտեր',
      rawPayload: 'Հում պատասխան',
      aiRemediation: 'AI վերականգնման պլան',
      monitoringTitle: 'Ենթակառուցվածքի մոնիտորինգ',
      monitoringSidebarHint: 'Ավելացրեք հոսթեր, հարցեք մետրիկները, ապա դիտեք AI միտումային որոշումները։',
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
      noData: 'Տվյալներ չկան'
    },
  };

  const STORAGE_KEY = 'audit_ui_lang';
  let currentLanguage = 'en';

  const languageSelect = document.getElementById('language-select');
  const pageName = document.body ? document.body.getAttribute('data-page') : '';

  function t(key) {
    const pack = UI_STRINGS[currentLanguage] || UI_STRINGS.en;
    return Object.prototype.hasOwnProperty.call(pack, key) ? pack[key] : UI_STRINGS.en[key] || key;
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
    items.forEach(function (it) {
      const li = document.createElement('li');
      li.textContent = String(it);
      ul.appendChild(li);
    });
    el.appendChild(ul);
  }

  function auditWireup() {
    const runBtn = document.getElementById('run-audit-button');
    const subnetInput = document.getElementById('subnet-input');
    const tableBody = document.getElementById('network-table-body');
    const anomalyCount = document.getElementById('anomaly-count');
    const remediationList = document.getElementById('remediation-list');
    const rawEl = document.getElementById('audit-raw');
    if (!runBtn) return;
    runBtn.addEventListener('click', async function () {
      runBtn.disabled = true;
      try {
        clearElement(tableBody);
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
        const planLines = plan.map(function (p) { return String(p.title || '') + ': ' + String(p.resolution_steps || ''); });
        renderList(remediationList, planLines);
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
    const metricsBody = document.getElementById('metrics-table-body');
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

    function showView(name) {
      [viewHosts, viewLive, viewAi].forEach(function (v) { if (v) v.classList.remove('active'); });
      if (name === 'hosts' && viewHosts) viewHosts.classList.add('active');
      if (name === 'live' && viewLive) viewLive.classList.add('active');
      if (name === 'ai' && viewAi) viewAi.classList.add('active');
      navButtons.forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-view') === name); });
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

    async function loadHosts() {
      const res = await jsonFetch('/api/hosts', 'GET');
      if (!res.ok) return;
      clearElement(hostsBody);
      const hosts = res.body && Array.isArray(res.body.hosts) ? res.body.hosts : [];
      hosts.forEach(function (h) {
        const tr = document.createElement('tr');
        [h.id, h.hostname, h.ip_address, h.device_type, h.date_added].forEach(function (v) {
          const td = document.createElement('td');
          td.textContent = v === undefined || v === null ? '' : String(v);
          tr.appendChild(td);
        });
        const tdActions = document.createElement('td');
        const editBtn = document.createElement('button');
        editBtn.textContent = t('edit');
        editBtn.addEventListener('click', function () {
          fillHostForm(h);
          showView('hosts');
        });
        const delBtn = document.createElement('button');
        delBtn.textContent = t('delete');
        delBtn.style.marginLeft = '8px';
        delBtn.addEventListener('click', async function () {
          const resDel = await jsonFetch('/api/hosts', 'DELETE', { id: h.id });
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
      clearElement(metricsBody);
      const rows = res.body && Array.isArray(res.body.metrics) ? res.body.metrics : [];
      rows.forEach(function (m) {
        const tr = document.createElement('tr');
        [m.hostname, m.ip_address, m.device_type, m.cpu_utilization, m.ram_usage, m.disk_usage, m.temperature_c, m.status, m.polled_at].forEach(function (v) {
          const td = document.createElement('td');
          td.textContent = v === undefined || v === null ? '' : String(v);
          tr.appendChild(td);
        });
        metricsBody.appendChild(tr);
      });
    }

    async function pollMetrics() {
      const res = await jsonFetch('/api/metrics/poll', 'POST', {});
      if (!res.ok) return;
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
        const panel = document.createElement('div');
        panel.className = 'panel';
        const h = document.createElement('div');
        h.style.fontWeight = '900';
        h.textContent = String(d.hostname || '') + ' (' + String(d.ip_address || '') + ') - ' + String(d.title || '');
        const p1 = document.createElement('div');
        p1.className = 'muted';
        p1.style.marginTop = '8px';
        p1.textContent = String(d.trend_analysis || '');
        const p2 = document.createElement('div');
        p2.style.marginTop = '10px';
        p2.textContent = String(d.resolution_text || '');
        const pre = document.createElement('pre');
        const code = document.createElement('code');
        code.textContent = String(d.script || '');
        pre.appendChild(code);
        panel.appendChild(h);
        panel.appendChild(p1);
        panel.appendChild(p2);
        panel.appendChild(pre);
        aiRoot.appendChild(panel);
      });
    }

    if (refreshHosts) refreshHosts.addEventListener('click', loadHosts);
    if (createHost) createHost.addEventListener('click', createHostAction);
    if (updateHost) updateHost.addEventListener('click', updateHostAction);
    if (clearHost) clearHost.addEventListener('click', clearHostForm);
    if (pollBtn) pollBtn.addEventListener('click', pollMetrics);
    if (refreshMetrics) refreshMetrics.addEventListener('click', loadMetricsLatest);
    if (refreshAi) refreshAi.addEventListener('click', loadAiDecisions);

    loadHosts();
    loadMetricsLatest();
    loadAiDecisions();
  }

  if (pageName === 'audit') auditWireup();
  if (pageName === 'monitoring') monitoringWireup();
})();
