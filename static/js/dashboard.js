document.addEventListener('DOMContentLoaded', function() {
    // Initialize loading states
    function showLoading(element) {
        if (!element) return;
        const loadingDiv = document.createElement('div');
        loadingDiv.className = 'loading-indicator';
        loadingDiv.innerHTML = `
            <div class="spinner"></div>
            <span>Loading...</span>
        `;
        element.classList.add('loading');
        element.appendChild(loadingDiv);
        element.setAttribute('disabled', 'true');
    }

    function hideLoading(element) {
        if (!element) return;
        const loadingIndicator = element.querySelector('.loading-indicator');
        if (loadingIndicator) {
            loadingIndicator.remove();
        }
        element.classList.remove('loading');
        element.removeAttribute('disabled');
    }

    // Modal functionality
    window.showModal = function(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.style.display = 'block';
        }
    }

    window.hideModal = function(modalId) {
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

    // Make loading functions globally available
    window.showLoading = showLoading;
    window.hideLoading = hideLoading;
});
