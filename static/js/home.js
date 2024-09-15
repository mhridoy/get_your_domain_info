document.addEventListener('DOMContentLoaded', () => {
    const themeToggle = document.getElementById('theme-toggle');
    const form = document.getElementById('certificate-form');
    const result = document.getElementById('result');
    const certificateDetails = document.getElementById('certificate-details');
    const subdomainsList = document.getElementById('subdomains-list');
    const progressBar = document.getElementById('progress-bar');

    themeToggle.addEventListener('click', () => {
        document.documentElement.classList.toggle('dark');
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const domain = document.getElementById('domain').value;

        // Show progress bar
        progressBar.classList.remove('hidden');
        progressBar.style.width = '0%';

        try {
            // Simulate progress
            let progress = 0;
            const progressInterval = setInterval(() => {
                progress += 10;
                progressBar.style.width = `${progress}%`;
                if (progress >= 90) clearInterval(progressInterval);
            }, 200);

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

            // Complete progress bar
            clearInterval(progressInterval);
            progressBar.style.width = '100%';

            setTimeout(() => {
                progressBar.classList.add('hidden');
                displayCertificateInfo(certificateData);
                displaySubdomains(subdomainsData);
                result.classList.remove('hidden');
            }, 500);

        } catch (error) {
            console.error('Error:', error);
            alert(`An error occurred while fetching the data: ${error.message}. Please try again.`);
            progressBar.classList.add('hidden');
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
        if (!data || data.length === 0) {
            subdomainsList.innerHTML = '<li class="text-red-500">No subdomains found</li>';
        } else {
            subdomainsList.innerHTML = data.map(subdomain => `<li class="text-green-500">${subdomain}</li>`).join('');
        }
    }
});