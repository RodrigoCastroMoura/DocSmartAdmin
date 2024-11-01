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

    // API Response Handler
    async function handleApiResponse(response, successCallback, errorCallback) {
        try {
            if (response.ok) {
                const data = await response.json().catch(() => ({}));
                if (successCallback) await successCallback(data);
                return true;
            } else {
                const error = await response.json().catch(() => ({ error: 'An error occurred' }));
                showErrorMessage(error.error || 'Operation failed');
                if (errorCallback) await errorCallback(error);
                return false;
            }
        } catch (error) {
            showErrorMessage('An unexpected error occurred');
            if (errorCallback) await errorCallback(error);
            return false;
        }
    }

    // Error Message Display
    function showErrorMessage(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-toast';
        errorDiv.textContent = message;
        document.body.appendChild(errorDiv);

        setTimeout(() => {
            errorDiv.classList.add('show');
            setTimeout(() => {
                errorDiv.classList.remove('show');
                setTimeout(() => errorDiv.remove(), 300);
            }, 3000);
        }, 100);
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

    // Make functions globally available
    window.showLoading = showLoading;
    window.hideLoading = hideLoading;
    window.handleApiResponse = handleApiResponse;
    window.showErrorMessage = showErrorMessage;
});
