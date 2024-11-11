// Error handling utilities
function getErrorMessage(error, defaultMessage = 'An error occurred') {
    if (typeof error === 'string') return error;
    if (error && error.message) return error.message;
    if (error && error.error) return error.error;
    if (error && Object.keys(error).length === 0) return defaultMessage;
    return defaultMessage;
}

// Loading state management
function showLoading(element) {
    if (!element) return;
    
    // Create loading overlay if it doesn't exist
    let loadingOverlay = element.querySelector('.loading-overlay');
    if (!loadingOverlay) {
        loadingOverlay = document.createElement('div');
        loadingOverlay.className = 'loading-overlay';
        loadingOverlay.innerHTML = '<i data-feather="loader"></i>';
        element.style.position = 'relative';
        element.appendChild(loadingOverlay);
        feather.replace();
    }
    loadingOverlay.style.display = 'flex';
}

function hideLoading(element) {
    if (!element) return;
    const loadingOverlay = element.querySelector('.loading-overlay');
    if (loadingOverlay) {
        loadingOverlay.style.display = 'none';
    }
}

// API request wrapper with error handling
async function apiRequest(url, options = {}) {
    const defaultOptions = {
        headers: {
            'Accept': 'application/json'
        }
    };
    
    const finalOptions = { ...defaultOptions, ...options };
    
    try {
        const response = await fetch(url, finalOptions);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(getErrorMessage(data, `Request failed with status ${response.status}`));
        }
        
        return data;
    } catch (error) {
        console.error('API request error:', error);
        throw new Error(getErrorMessage(error, 'Failed to complete request'));
    }
}
