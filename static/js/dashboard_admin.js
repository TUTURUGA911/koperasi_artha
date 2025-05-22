// Format numbers to millions or billions
function formatToMillionsOrBillions(number) {
    if (number >= 1000000000) {
        return (number / 1000000000).toFixed(2) + ' M';
    } else if (number >= 1000000) {
        return (number / 1000000).toFixed(2) + ' juta';
    } else {
        return number.toString();
    }
}

// Update values to millions or billions format
function updateValuesToMillionsOrBillions() {
    const savingsValue = document.getElementById('total-savings-value');
    const loansValue = document.getElementById('total-loans-value');
    const incomeValue = document.getElementById('total-income-value');

    const savingsText = savingsValue.textContent.replace(/[^\d]/g, '');
    const loansText = loansValue.textContent.replace(/[^\d]/g, '');
    const incomeText = incomeValue.textContent.replace(/[^\d]/g, '');

    const savingsNumber = parseInt(savingsText, 10);
    const loansNumber = parseInt(loansText, 10);
    const incomeNumber = parseInt(incomeText, 10);

    savingsValue.textContent = 'Rp ' + formatToMillionsOrBillions(savingsNumber);
    loansValue.textContent = 'Rp ' + formatToMillionsOrBillions(loansNumber);
    incomeValue.textContent = 'Rp ' + formatToMillionsOrBillions(incomeNumber);
}

// Filter member table rows
function filterMembers() {
    const input = document.getElementById('memberSearch');
    const filter = input.value.toLowerCase();
    const table = document.getElementById('membersTable');
    const trs = table.tBodies[0].getElementsByTagName('tr');

    for (let i = 0; i < trs.length; i++) {
        const tdName = trs[i].getElementsByTagName('td')[1];
        if (tdName) {
            let txtValue = tdName.textContent || tdName.innerText;
            trs[i].style.display = txtValue.toLowerCase().indexOf(filter) > -1 ? '' : 'none';
        }
    }
}

// Logout function
function logout() {
    Swal.fire({
        title: 'Apakah Anda yakin?',
        text: "Anda akan keluar!",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#2ecc71',
        cancelButtonColor: '#ef4444',
        confirmButtonText: 'Ya, keluar!',
        cancelButtonText: 'Batal'
    }).then((result) => {
        if (result.isConfirmed) {
            try {
                Cookies.remove('mytoken');
                Cookies.remove('mytoken', {
                    path: '/'
                });
                if ($ && $.removeCookie) {
                    $.removeCookie('mytoken');
                    $.removeCookie('mytoken', {
                        path: '/'
                    });
                }
                document.cookie = "mytoken=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
                Swal.fire(
                    'Keluar!',
                    'Anda telah berhasil keluar.',
                    'success'
                ).then(() => {
                    window.location.href = '/login';
                });
            } catch (error) {
                console.error("Error during logout:", error);
                window.location.href = '/login';
            }
        }
    });
}

// Toggle sidebar
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('overlay');
    sidebar.classList.toggle('active');
    overlay.classList.toggle('show');
}

// Toggle sidebar collapse
function toggleCollapse() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('collapsed');
}

// Toggle theme
function toggleTheme() {
    const body = document.body;
    const themeSwitch = document.getElementById('themeSwitch');
    if (themeSwitch.checked) {
        body.setAttribute('data-theme', 'dark');
        localStorage.setItem('theme', 'dark');
    } else {
        body.removeAttribute('data-theme');
        localStorage.setItem('theme', 'light');
    }
}

// Event listeners
document.addEventListener('DOMContentLoaded', function() {
    updateValuesToMillionsOrBillions();
    document.getElementById('logoutButton').addEventListener('click', logout);

    // Load saved theme
    const savedTheme = localStorage.getItem('theme');
    const themeSwitch = document.getElementById('themeSwitch');
    if (savedTheme === 'dark') {
        document.body.setAttribute('data-theme', 'dark');
        themeSwitch.checked = true;
    }
});