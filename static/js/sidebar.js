document.addEventListener('DOMContentLoaded', function() {
    const sidebar = document.getElementById('sidebar');
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const dashboardContainer = document.querySelector('.dashboard-container');

    sidebarToggle.addEventListener('click', function() {
        sidebar.classList.toggle('collapsed');
        if (window.innerWidth > 768) {
            dashboardContainer.style.gridTemplateColumns = 
                sidebar.classList.contains('collapsed') ? '70px 1fr' : '250px 1fr';
        }
    });

    // Handle responsive behavior
    function handleResize() {
        if (window.innerWidth <= 768) {
            dashboardContainer.style.gridTemplateColumns = '70px 1fr';
            sidebar.classList.add('collapsed');
        } else {
            if (!sidebar.classList.contains('collapsed')) {
                dashboardContainer.style.gridTemplateColumns = '250px 1fr';
            }
        }
    }

    window.addEventListener('resize', handleResize);
    handleResize(); // Initial check
});
