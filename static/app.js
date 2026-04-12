(function () {
  const runAuditButton = document.getElementById('run-audit-button');
  const subnetInput = document.getElementById('subnet-input');
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

  function setLoadingState(isLoading) {
    if (isLoading) {
      loadingOverlay.classList.remove('hidden');
      loadingOverlay.setAttribute('aria-hidden', 'false');
      runAuditButton.disabled = true;
      if (subnetInput) {
        subnetInput.disabled = true;
      }
    } else {
      loadingOverlay.classList.add('hidden');
      loadingOverlay.setAttribute('aria-hidden', 'true');
      runAuditButton.disabled = false;
      if (subnetInput) {
        subnetInput.disabled = false;
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
    auditTimestamp.textContent = 'Last run: ' + instant.toLocaleString();
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
      assetRowCount.textContent = '0 endpoints';
      const emptyRow = document.createElement('tr');
      const emptyCell = document.createElement('td');
      emptyCell.colSpan = 5;
      emptyCell.textContent = 'No listening sockets were returned by the scanner.';
      emptyCell.style.color = '#94a3b8';
      emptyCell.style.fontStyle = 'italic';
      emptyRow.appendChild(emptyCell);
      assetsTableBody.appendChild(emptyRow);
      return;
    }
    assetRowCount.textContent = String(socketRows.length) + ' endpoints';
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
    titleElement.textContent = planItem && planItem.title ? String(planItem.title) : 'Remediation item';
    const pillElement = document.createElement('div');
    pillElement.className = 'confidence-pill';
    const labelElement = document.createElement('span');
    labelElement.className = 'confidence-label';
    labelElement.textContent = 'AI Confidence';
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
      remediationCount.textContent = '0 recommendations';
      const emptyState = document.createElement('div');
      emptyState.className = 'muted-chip';
      emptyState.style.display = 'inline-block';
      emptyState.style.marginTop = '6px';
      emptyState.textContent = 'No remediation matches were produced.';
      remediationGrid.appendChild(emptyState);
      return;
    }
    remediationCount.textContent = String(planItems.length) + ' recommendations';
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
      const requestBodyString =
        trimmedSubnetValue.length > 0
          ? JSON.stringify({ subnet: trimmedSubnetValue })
          : JSON.stringify({});
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
        showError('The server returned data that is not valid JSON.');
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
        showError('Unexpected empty response from audit service.');
        return;
      }
      renderDashboardFromPayload(parsedBody);
    } catch (networkError) {
      showError('Network error while contacting the audit API.');
    } finally {
      setLoadingState(false);
    }
  }

  runAuditButton.addEventListener('click', function () {
    handleRunAuditClick();
  });
})();
