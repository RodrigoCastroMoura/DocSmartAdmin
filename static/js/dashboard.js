document.addEventListener('DOMContentLoaded', function() {
    // Initialize loading states
    window.showLoading = function(element) {
        if (!element) return;
        const loadingDiv = document.createElement('div');
        loadingDiv.className = 'loading-indicator';
        loadingDiv.innerHTML = `
            <div class="spinner"></div>
            <span>Carregando...</span>
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

    // API Response Handler with improved error handling and Portuguese messages
    window.handleApiResponse = async function(response, successCallback, errorCallback) {
        try {
            let data;
            try {
                data = await response.json();
            } catch (e) {
                data = {};
            }

            const statusMessages = {
                201: 'Usuário criado com sucesso',
                400: 'Dados inválidos',
                401: 'Não autenticado',
                403: 'Não autorizado',
                404: 'Usuário não encontrado',
                409: 'Usuário já existe',
                500: 'Erro interno do servidor'
            };

            if (response.ok || response.status === 201) {
                if (successCallback) {
                    await successCallback(data);
                }
                if (response.status === 201) {
                    showErrorMessage(statusMessages[201], 'success');
                }
                return true;
            } else {
                const message = statusMessages[response.status] || data.error || 'Operação falhou';
                showErrorMessage(message);
                if (errorCallback) {
                    await errorCallback(data);
                }
                return false;
            }
        } catch (error) {
            console.error('API response handling error:', error);
            showErrorMessage('Ocorreu um erro inesperado');
            if (errorCallback) {
                await errorCallback(error);
            }
            return false;
        }
    }

    // Error Message Display with improved visibility
    window.showErrorMessage = function(message, type = 'error') {
        const existingToast = document.querySelector('.error-toast');
        if (existingToast) {
            existingToast.remove();
        }

        const errorDiv = document.createElement('div');
        errorDiv.className = `error-toast ${type}`;
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
            } else {
                console.error(`Modal não encontrado: ${modalId}`);
            }
        } catch (error) {
            console.error('Erro ao exibir modal:', error);
        }
    }

    window.hideModal = function(modalId) {
        try {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.style.display = 'none';
            } else {
                console.error(`Modal não encontrado: ${modalId}`);
            }
        } catch (error) {
            console.error('Erro ao ocultar modal:', error);
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
        console.error('Erro não tratado:', event.reason);
        showErrorMessage('Ocorreu um erro inesperado. Tente novamente.');
        event.preventDefault();
    });

    // Network status monitoring
    window.addEventListener('online', function() {
        showErrorMessage('Conexão restaurada', 'success');
    });

    window.addEventListener('offline', function() {
        showErrorMessage('Sem conexão com a internet');
    });
});
