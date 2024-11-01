// Form validation utilities
const ValidationRules = {
    required: (value) => value && value.trim() !== '' ? '' : 'This field is required',
    email: (value) => {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(value) ? '' : 'Please enter a valid email address';
    },
    minLength: (length) => (value) => 
        value.length >= length ? '' : `Must be at least ${length} characters long`,
    maxLength: (length) => (value) => 
        value.length <= length ? '' : `Must not exceed ${length} characters`,
    match: (matchId, message) => (value) => {
        const matchElement = document.getElementById(matchId);
        return matchElement.value === value ? '' : message;
    }
};

// Show error message next to input
function showError(input, message) {
    const formGroup = input.closest('.form-group');
    let errorDiv = formGroup.querySelector('.error-message');
    
    if (!errorDiv) {
        errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        formGroup.appendChild(errorDiv);
    }
    
    errorDiv.textContent = message;
    input.classList.add('error');
}

// Clear error message
function clearError(input) {
    const formGroup = input.closest('.form-group');
    const errorDiv = formGroup.querySelector('.error-message');
    
    if (errorDiv) {
        errorDiv.remove();
    }
    input.classList.remove('error');
}

// Validate a single field
function validateField(input, rules) {
    clearError(input);
    
    for (const rule of rules) {
        const error = rule(input.value);
        if (error) {
            showError(input, error);
            return false;
        }
    }
    
    return true;
}

// Validate entire form
function validateForm(form, validationConfig) {
    let isValid = true;
    
    for (const [fieldId, rules] of Object.entries(validationConfig)) {
        const field = form.querySelector(`#${fieldId}`);
        if (field && !validateField(field, rules)) {
            isValid = false;
        }
    }
    
    return isValid;
}

// Add real-time validation to form
function setupFormValidation(formId, validationConfig) {
    const form = document.getElementById(formId);
    if (!form) return;
    
    // Add validation styles
    const style = document.createElement('style');
    style.textContent = `
        .error-message {
            color: var(--danger-color);
            font-size: 0.875rem;
            margin-top: 0.25rem;
        }
        
        .form-group input.error,
        .form-group select.error {
            border: 1px solid var(--danger-color);
        }
    `;
    document.head.appendChild(style);
    
    // Add real-time validation
    for (const [fieldId, rules] of Object.entries(validationConfig)) {
        const field = form.querySelector(`#${fieldId}`);
        if (field) {
            field.addEventListener('input', () => validateField(field, rules));
            field.addEventListener('blur', () => validateField(field, rules));
        }
    }
    
    // Validate on submit
    form.addEventListener('submit', function(event) {
        if (!validateForm(form, validationConfig)) {
            event.preventDefault();
        }
    });
}
