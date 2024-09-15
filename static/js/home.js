document.addEventListener('DOMContentLoaded', () => {
    const themeToggle = document.getElementById('theme-toggle');
    const form = document.getElementById('certificate-form');
    const result = document.getElementById('result');
    const certificateDetails = document.getElementById('certificate-details');
    const subdomainsList = document.getElementById('subdomains-list');

    themeToggle.addEventListener('click', () => {
        document.documentElement.classList.toggle('dark');
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const domain = document.getElementById('domain').value;

        try {
            const [certificateResponse, subdomainsResponse] = await Promise.all([
                fetch('/api/certificate', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ domain }),
                }),
                fetch('/api/subdomains', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ domain }),
                })
            ]);

            const certificateData = await certificateResponse.json();
            const subdomainsData = await subdomainsResponse.json();

            displayCertificateInfo(certificateData);
            displaySubdomains(subdomainsData);

            result.classList.remove('hidden');
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred while fetching the data. Please try again.');
        }
    });

    function displayCertificateInfo(data) {
        certificateDetails.innerHTML = `
            <tr><td class="border px-4 py-2"><strong>Common Name:</strong></td><td class="border px-4 py-2">${data.common_name}</td></tr>
            <tr><td class="border px-4 py-2"><strong>Issuer:</strong></td><td class="border px-4 py-2">${data.issuer}</td></tr>
            <tr><td class="border px-4 py-2"><strong>Valid From:</strong></td><td class="border px-4 py-2">${data.valid_from}</td></tr>
            <tr><td class="border px-4 py-2"><strong>Valid To:</strong></td><td class="border px-4 py-2">${data.valid_to}</td></tr>
            <tr><td class="border px-4 py-2"><strong>IP Address:</strong></td><td class="border px-4 py-2">${data.ip_address}</td></tr>
        `;
    }

    function displaySubdomains(data) {
        if (data.subdomains.length === 0) {
            subdomainsList.innerHTML = '<li>No subdomains found</li>';
        } else {
            subdomainsList.innerHTML = data.subdomains.map(subdomain => `<li>${subdomain}</li>`).join('');
        }
        // Display SANs if available
        if (data.san && data.san.length > 0) {
            subdomainsList.innerHTML += '<li><strong>Subject Alternative Names:</strong></li>';
            subdomainsList.innerHTML += data.san.map(san => `<li>${san[1]}</li>`).join('');
        }
    }
});