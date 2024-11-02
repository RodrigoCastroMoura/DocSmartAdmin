// Form validation utilities
window.ValidationRules = window.ValidationRules || {
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
    },
    cpf: (value) => {
        const cpfRegex = /^\d{11}$/;
        return cpfRegex.test(value) ? '' : 'Please enter a valid CPF (11 digits)';
    },
    phone: (value) => {
        if (!value) return ''; // Phone is optional
        const phoneRegex = /^\d{10,11}$/;
        return phoneRegex.test(value) ? '' : 'Please enter a valid phone number';
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
    
    if (!validationConfig || typeof validationConfig !== 'object') {
        return true;
    }
    
    for (const [fieldId, rules] of Object.entries(validationConfig)) {
        const field = form.querySelector(`#${fieldId}`);
        if (field && !validateField(field, rules)) {
            isValid = false;
        }
    }
    
    return isValid;
}

// Add real-time validation to form
window.setupFormValidation = function(formId, validationConfig) {
    const form = document.getElementById(formId);
    if (!form || !validationConfig) return;
    
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
};
