document.addEventListener('DOMContentLoaded', () => {
    const themeToggle = document.getElementById('theme-toggle');
    const form = document.getElementById('domain-form');
    const results = document.getElementById('results');
    const progressContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    const errorDisplay = document.getElementById('error-display');
    const errorMessage = document.getElementById('error-message');

    // Theme toggle functionality
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            document.documentElement.classList.toggle('dark');
        });
    }

    // Tab functionality
    function initializeTabs() {
        const tabButtons = document.querySelectorAll('.tab-button');
        const tabPanes = document.querySelectorAll('.tab-pane');

        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const targetTab = button.getAttribute('data-tab');

                // Update active tab button
                tabButtons.forEach(btn => {
                    btn.classList.remove('active', 'border-blue-500', 'text-blue-600');
                    btn.classList.add('border-transparent', 'text-gray-500');
                });
                button.classList.add('active', 'border-blue-500', 'text-blue-600');
                button.classList.remove('border-transparent', 'text-gray-500');

                // Show corresponding tab pane
                tabPanes.forEach(pane => {
                    pane.classList.add('hidden');
                    pane.classList.remove('active');
                });
                const targetPane = document.getElementById(`${targetTab}-tab`);
                if (targetPane) {
                    targetPane.classList.remove('hidden');
                    targetPane.classList.add('active');
                }
            });
        });
    }

    // Progress simulation
    function simulateProgress() {
        const steps = [
            { progress: 10, text: 'Validating domain...' },
            { progress: 25, text: 'Fetching SSL certificate...' },
            { progress: 40, text: 'Analyzing DNS records...' },
            { progress: 55, text: 'Extracting WHOIS information...' },
            { progress: 70, text: 'Discovering subdomains...' },
            { progress: 85, text: 'Scanning for email addresses...' },
            { progress: 95, text: 'Generating security analysis...' },
            { progress: 100, text: 'Analysis complete!' }
        ];

        let currentStep = 0;
        const stepInterval = setInterval(() => {
            if (currentStep < steps.length) {
                const step = steps[currentStep];
                progressBar.style.width = `${step.progress}%`;
                progressText.textContent = step.text;
                currentStep++;
            } else {
                clearInterval(stepInterval);
            }
        }, 500);

        return stepInterval;
    }

    // Form submission
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const domain = document.getElementById('domain').value.trim();

        if (!domain) {
            showError('Please enter a domain name');
            return;
        }

        // Show progress and hide previous results
        showProgress();
        hideError();
        results.classList.add('hidden');

        // Start progress simulation
        const progressInterval = simulateProgress();

        try {
            const response = await fetch('/api/domain-info', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ domain }),
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();

            // Clear progress simulation and complete
            clearInterval(progressInterval);
            setTimeout(() => {
                hideProgress();
                displayResults(data);
            }, 500);

        } catch (error) {
            clearInterval(progressInterval);
            hideProgress();
            showError(`Analysis failed: ${error.message}`);
        }
    });

    function showProgress() {
        progressContainer.classList.remove('hidden');
        progressBar.style.width = '0%';
        progressText.textContent = 'Initializing analysis...';
        
        // Update form button
        const button = form.querySelector('button[type="submit"]');
        button.disabled = true;
        button.querySelector('.analyze-text').classList.add('hidden');
        button.querySelector('.loading-text').classList.remove('hidden');
    }

    function hideProgress() {
        progressContainer.classList.add('hidden');
        
        // Reset form button
        const button = form.querySelector('button[type="submit"]');
        button.disabled = false;
        button.querySelector('.analyze-text').classList.remove('hidden');
        button.querySelector('.loading-text').classList.add('hidden');
    }

    function showError(message) {
        errorMessage.textContent = message;
        errorDisplay.classList.remove('hidden');
    }

    function hideError() {
        errorDisplay.classList.add('hidden');
    }

    function displayResults(data) {
        // Display summary scores
        displaySummaryScores(data.summary || {});
        
        // Display different sections
        displayOverview(data);
        displayCertificate(data.certificate || {});
        displayEmails(data.all_emails || {});
        displaySubdomains(data.subdomains || {});
        displayDNS(data.dns_records || {});
        displayWHOIS(data.whois || {});
        displaySecurity(data);

        // Initialize tabs and show results
        initializeTabs();
        results.classList.remove('hidden');
    }

    function displaySummaryScores(summary) {
        const overallScore = summary.overall_score || 0;
        const securityScore = summary.security_score || 0;
        const trustScore = summary.trust_score || 0;

        document.getElementById('overall-score').textContent = overallScore;
        document.getElementById('security-score').textContent = securityScore;
        document.getElementById('trust-score').textContent = trustScore;

        document.getElementById('overall-score-bar').style.width = `${overallScore}%`;
        document.getElementById('security-score-bar').style.width = `${securityScore}%`;
        document.getElementById('trust-score-bar').style.width = `${trustScore}%`;
    }

    function displayOverview(data) {
        const keyFindingsList = document.getElementById('key-findings');
        const recommendationsList = document.getElementById('recommendations');
        const technologyStack = document.getElementById('technology-stack');

        // Key findings
        const findings = data.summary?.key_findings || [];
        keyFindingsList.innerHTML = findings.length > 0 
            ? findings.map(finding => `<li class="flex items-center"><span class="text-green-500 mr-2">✓</span>${finding}</li>`).join('')
            : '<li class="text-gray-500">No specific findings to report</li>';

        // Recommendations
        const recommendations = data.summary?.recommendations || [];
        recommendationsList.innerHTML = recommendations.length > 0
            ? recommendations.map(rec => `<li class="flex items-center"><span class="text-yellow-500 mr-2">⚠</span>${rec}</li>`).join('')
            : '<li class="text-green-500 flex items-center"><span class="mr-2">✓</span>No recommendations needed</li>';

        // Technology stack
        const tech = data.technology_stack || {};
        const techItems = [
            { label: 'Web Server', value: tech.web_server || 'Unknown' },
            { label: 'CMS', value: tech.cms || 'Unknown' },
            { label: 'CDN', value: tech.cdn || 'Unknown' },
            { label: 'Frameworks', value: tech.frameworks?.join(', ') || 'None detected' }
        ];

        technologyStack.innerHTML = techItems.map(item => `
            <div class="bg-gray-100 dark:bg-gray-700 p-3 rounded">
                <div class="font-semibold text-sm">${item.label}</div>
                <div class="text-xs text-gray-600 dark:text-gray-400">${item.value}</div>
            </div>
        `).join('');
    }

    function displayCertificate(cert) {
        const container = document.querySelector('#certificate-details table');
        
        if (cert.error) {
            container.innerHTML = `<tr><td colspan="2" class="px-4 py-2 text-red-500">Error: ${cert.error}</td></tr>`;
            return;
        }

        const certData = [
            ['Common Name', cert.common_name || 'N/A'],
            ['Issuer', cert.issuer || 'N/A'],
            ['Valid From', cert.valid_from ? new Date(cert.valid_from).toLocaleDateString() : 'N/A'],
            ['Valid To', cert.valid_to ? new Date(cert.valid_to).toLocaleDateString() : 'N/A'],
            ['Days Until Expiry', cert.days_until_expiry || 'N/A'],
            ['Status', cert.is_expired ? '❌ Expired' : cert.expires_soon ? '⚠️ Expires Soon' : '✅ Valid'],
            ['Protocol Version', cert.protocol_version || 'N/A'],
            ['Cipher Suite', cert.cipher_suite || 'N/A'],
            ['Is Wildcard', cert.is_wildcard ? 'Yes' : 'No'],
            ['Serial Number', cert.serial_number || 'N/A']
        ];

        container.innerHTML = `
            <thead class="bg-gray-50 dark:bg-gray-700">
                <tr><th class="px-4 py-2 text-left">Field</th><th class="px-4 py-2 text-left">Value</th></tr>
            </thead>
            <tbody>
                ${certData.map(([field, value]) => `
                    <tr class="border-b dark:border-gray-700">
                        <td class="px-4 py-2 font-medium">${field}</td>
                        <td class="px-4 py-2">${value}</td>
                    </tr>
                `).join('')}
            </tbody>
        `;
    }

    function displayEmails(emailData) {
        const container = document.getElementById('emails-content');
        
        if (!emailData.emails || emailData.emails.length === 0) {
            container.innerHTML = '<p class="text-gray-500">No email addresses found</p>';
            return;
        }

        const emailsBySource = {
            whois: emailData.sources?.whois || 0,
            website: emailData.sources?.website || 0,
            dns: emailData.sources?.dns || 0
        };

        container.innerHTML = `
            <div class="mb-4">
                <h4 class="font-semibold mb-2">Found ${emailData.count} email address(es):</h4>
                <div class="grid gap-2">
                    ${emailData.emails.map(email => `
                        <div class="bg-gray-100 dark:bg-gray-700 p-3 rounded flex justify-between items-center">
                            <code class="text-blue-600 dark:text-blue-400">${email}</code>
                            <button onclick="navigator.clipboard.writeText('${email}')" class="text-xs bg-blue-500 text-white px-2 py-1 rounded hover:bg-blue-600">
                                Copy
                            </button>
                        </div>
                    `).join('')}
                </div>
            </div>
            <div class="text-sm text-gray-600 dark:text-gray-400">
                <p>Sources: WHOIS (${emailsBySource.whois}), Website (${emailsBySource.website}), DNS (${emailsBySource.dns})</p>
            </div>
        `;
    }

    function displaySubdomains(subdomainData) {
        const container = document.getElementById('subdomains-content');
        
        if (!subdomainData.subdomains || subdomainData.subdomains.length === 0) {
            container.innerHTML = '<p class="text-gray-500">No subdomains discovered</p>';
            return;
        }

        container.innerHTML = `
            <div class="mb-4">
                <h4 class="font-semibold mb-2">Found ${subdomainData.count} subdomain(s):</h4>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-96 overflow-y-auto">
                    ${subdomainData.subdomains.map(subdomain => `
                        <div class="bg-gray-100 dark:bg-gray-700 p-2 rounded">
                            <code class="text-green-600 dark:text-green-400">${subdomain}</code>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    function displayDNS(dnsData) {
        const container = document.getElementById('dns-content');
        
        if (!dnsData || Object.keys(dnsData).length === 0) {
            container.innerHTML = '<p class="text-gray-500">No DNS records found</p>';
            return;
        }

        const recordSections = Object.entries(dnsData).map(([type, records]) => {
            if (!records || records.length === 0) return '';
            
            return `
                <div class="bg-gray-100 dark:bg-gray-700 p-4 rounded">
                    <h4 class="font-semibold mb-2">${type} Records</h4>
                    <div class="space-y-1">
                        ${records.map(record => {
                            if (typeof record === 'object') {
                                return `<div class="text-sm font-mono">${JSON.stringify(record, null, 2)}</div>`;
                            }
                            return `<div class="text-sm font-mono">${record}</div>`;
                        }).join('')}
                    </div>
                </div>
            `;
        }).filter(section => section !== '');

        container.innerHTML = recordSections.join('');
    }

    function displayWHOIS(whoisData) {
        const container = document.querySelector('#whois-content table');
        
        if (whoisData.error) {
            container.innerHTML = `<tr><td colspan="2" class="px-4 py-2 text-red-500">Error: ${whoisData.error}</td></tr>`;
            return;
        }

        const whoisFields = [
            ['Domain Name', whoisData.domain_name],
            ['Registrar', whoisData.registrar],
            ['Creation Date', whoisData.creation_date],
            ['Expiration Date', whoisData.expiration_date],
            ['Updated Date', whoisData.updated_date],
            ['Organization', whoisData.organization],
            ['Country', whoisData.country],
            ['State', whoisData.state],
            ['City', whoisData.city],
            ['Name Servers', Array.isArray(whoisData.name_servers) ? whoisData.name_servers.join(', ') : whoisData.name_servers],
            ['Status', Array.isArray(whoisData.status) ? whoisData.status.join(', ') : whoisData.status]
        ].filter(([_, value]) => value && value !== 'None');

        container.innerHTML = `
            <thead class="bg-gray-50 dark:bg-gray-700">
                <tr><th class="px-4 py-2 text-left">Field</th><th class="px-4 py-2 text-left">Value</th></tr>
            </thead>
            <tbody>
                ${whoisFields.map(([field, value]) => `
                    <tr class="border-b dark:border-gray-700">
                        <td class="px-4 py-2 font-medium">${field}</td>
                        <td class="px-4 py-2">${value}</td>
                    </tr>
                `).join('')}
            </tbody>
        `;
    }

    function displaySecurity(data) {
        const headersContainer = document.getElementById('security-headers');
        const portsContainer = document.getElementById('open-ports');
        const reputationContainer = document.getElementById('domain-reputation');

        // Security headers
        const headers = data.http_headers?.security_headers || {};
        const headerItems = Object.entries(headers).map(([header, value]) => {
            const isSet = value !== 'Not Set';
            return `
                <div class="flex justify-between items-center p-2 border rounded">
                    <span class="font-medium">${header.replace(/_/g, '-').toUpperCase()}</span>
                    <span class="${isSet ? 'text-green-600' : 'text-red-600'}">
                        ${isSet ? '✅ Set' : '❌ Not Set'}
                    </span>
                </div>
            `;
        });
        headersContainer.innerHTML = headerItems.join('');

        // Open ports
        const ports = data.port_scan || [];
        if (ports.length > 0) {
            portsContainer.innerHTML = `
                <div class="grid grid-cols-4 gap-2">
                    ${ports.map(port => `
                        <span class="bg-red-100 text-red-800 px-2 py-1 rounded text-sm">${port}</span>
                    `).join('')}
                </div>
            `;
        } else {
            portsContainer.innerHTML = '<p class="text-gray-500">No common ports detected as open</p>';
        }

        // Domain reputation
        const reputation = data.reputation || {};
        const riskFactors = reputation.risk_factors || [];
        const trustIndicators = reputation.trust_indicators || [];
        
        reputationContainer.innerHTML = `
            <div class="space-y-3">
                <div class="p-3 rounded ${reputation.is_suspicious ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}">
                    <strong>${reputation.is_suspicious ? '⚠️ Potentially Suspicious' : '✅ Appears Safe'}</strong>
                </div>
                ${riskFactors.length > 0 ? `
                    <div>
                        <h5 class="font-semibold text-red-600 mb-2">Risk Factors:</h5>
                        <ul class="space-y-1">
                            ${riskFactors.map(factor => `<li class="text-sm">• ${factor}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
                ${trustIndicators.length > 0 ? `
                    <div>
                        <h5 class="font-semibold text-green-600 mb-2">Trust Indicators:</h5>
                        <ul class="space-y-1">
                            ${trustIndicators.map(indicator => `<li class="text-sm">• ${indicator}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
            </div>
        `;
    }
});