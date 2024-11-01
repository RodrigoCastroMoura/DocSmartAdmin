document.addEventListener('DOMContentLoaded', function() {
    // Initialize loading states
    function showLoading(element) {
        element.classList.add('loading');
    }

    function hideLoading(element) {
        element.classList.remove('loading');
    }

    // Modal functionality
    function showModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.style.display = 'block';
        }
    }

    function hideModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.style.display = 'none';
        }
    }

    // Close modals when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target.classList.contains('modal')) {
            event.target.style.display = 'none';
        }
    });

    // Simulate loading states for dynamic content
    const contentSections = document.querySelectorAll('.content-section');
    contentSections.forEach(section => {
        showLoading(section);
        setTimeout(() => {
            hideLoading(section);
        }, 1000);
    });
});
