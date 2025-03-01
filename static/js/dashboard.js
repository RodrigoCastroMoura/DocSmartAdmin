document.addEventListener('DOMContentLoaded', function() {
    // Initialize loading states
    window.showLoading = function(element) {
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

    window.hideLoading = function(element) {
        if (!element) return;
        const loadingIndicator = element.querySelector('.loading-indicator');
        if (loadingIndicator) {
            loadingIndicator.remove();
        }
        element.classList.remove('loading');
        element.removeAttribute('disabled');
    }

    // API Response Handler with improved error handling
    window.handleApiResponse = async function(response, successCallback, errorCallback) {
        try {
            let data;
            try {
                data = await response.json();
            } catch (e) {
                data = {};
            }

            if (response.ok) {
                if (successCallback) {
                    await successCallback(data);
                }
                return true;
            } else {
                const errorMessage = data.error || 'Operation failed';
                showErrorMessage(errorMessage);
                if (errorCallback) {
                    await errorCallback(data);
                }
                return false;
            }
        } catch (error) {
            console.error('API response handling error:', error);
            showErrorMessage('An unexpected error occurred');
            if (errorCallback) {
                await errorCallback(error);
            }
            return false;
        }
    }

    // Error Message Display with improved visibility
    window.showErrorMessage = function(message) {
        const existingToast = document.querySelector('.error-toast');
        if (existingToast) {
            existingToast.remove();
        }

        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-toast';
        errorDiv.textContent = message;
        document.body.appendChild(errorDiv);

        // Use RAF to ensure DOM update before animation
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                errorDiv.classList.add('show');
                setTimeout(() => {
                    errorDiv.classList.remove('show');
                    setTimeout(() => errorDiv.remove(), 300);
                }, 3000);
            });
        });
    }

    // Modal functionality with error handling
    window.showModal = function(modalId) {
        try {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.style.display = 'block';
                document.body.style.overflow = 'hidden'; // Bloqueia rolagem da página de fundo
                modal.style.overflow = 'auto'; // Permite rolagem dentro do modal
            } else {
                console.error(`Modal with id ${modalId} not found`);
            }
        } catch (error) {
            console.error('Error showing modal:', error);
        }
    }

    window.hideModal = function(modalId) {
        try {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.style.display = 'none';
                document.body.style.overflow = ''; // Restaura rolagem normal
            } else {
                console.error(`Modal with id ${modalId} not found`);
            }
        } catch (error) {
            console.error('Error hiding modal:', error);
        }
    }
    
    // Close modals when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target.classList.contains('modal')) {
            event.target.style.display = 'none';
        }
    });

    // Global error handler for fetch operations
    window.addEventListener('unhandledrejection', function(event) {
        console.error('Unhandled promise rejection:', event.reason);
        showErrorMessage('An unexpected error occurred. Please try again.');
        event.preventDefault();
    });

    // Network status monitoring
    window.addEventListener('online', function() {
        showErrorMessage('Connection restored');
    });

    window.addEventListener('offline', function() {
        showErrorMessage('No internet connection');
    });
});
