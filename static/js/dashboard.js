
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
                const errorMessage = data.error || 'Operação falhou';
                showErrorMessage(errorMessage);
                if (errorCallback) {
                    await errorCallback(data);
                }
                return false;
            }
        } catch (error) {
            console.error('Erro no processamento da resposta da API:', error);
            showErrorMessage('Ocorreu um erro inesperado');
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
                console.error(`Modal com id ${modalId} não encontrado`);
            }
        } catch (error) {
            console.error('Erro ao mostrar modal:', error);
        }
    }

    window.hideModal = function(modalId) {
        try {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.style.display = 'none';
                document.body.style.overflow = ''; // Restaura rolagem normal
            } else {
                console.error(`Modal com id ${modalId} não encontrado`);
            }
        } catch (error) {
            console.error('Erro ao esconder modal:', error);
        }
    }
    
    // Close modals when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target.classList.contains('modal')) {
            event.stopPropagation();
            const modalContent = event.target.querySelector('.modal-content');
            if (!modalContent || !modalContent.contains(event.target)) {
                hideModal(event.target.id);
            }
        }
    });

    // Global error handler for fetch operations
    window.addEventListener('unhandledrejection', function(event) {
        console.error('Rejeição de promessa não tratada:', event.reason);
        showErrorMessage('Ocorreu um erro inesperado. Por favor, tente novamente.');
        event.preventDefault();
    });

    // Network status monitoring
    window.addEventListener('online', function() {
        showErrorMessage('Conexão restaurada');
    });

    window.addEventListener('offline', function() {
        showErrorMessage('Sem conexão com a internet');
    });
});
