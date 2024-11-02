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
    passwordMatch: (value, form) => {
        const password = form.querySelector('#userPassword').value;
        return value === password ? '' : 'Passwords do not match';
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

// Apply phone mask
function applyPhoneMask(input) {
    let value = input.value.replace(/\D/g, '');
    if (value.length <= 11) {
        value = value.replace(/^(\d{2})(\d)/g, '($1) $2');
        value = value.replace(/(\d)(\d{4})$/, '$1-$2');
    }
    input.value = value;
}

// Validate a single field
function validateField(input, rules, form) {
    clearError(input);
    
    for (const rule of rules) {
        const error = rule(input.value, form);
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
        if (field && !validateField(field, rules, form)) {
            isValid = false;
        }
    }
    
    return isValid;
}

// Add real-time validation to form
window.setupFormValidation = function(formId, validationConfig) {
    const form = document.getElementById(formId);
    if (!form || !validationConfig) return;
    
    // Setup phone mask
    const phoneInputs = form.querySelectorAll('input[data-mask="(00) 00000-0000"]');
    phoneInputs.forEach(input => {
        input.addEventListener('input', () => applyPhoneMask(input));
    });
    
    // Add real-time validation
    for (const [fieldId, rules] of Object.entries(validationConfig)) {
        const field = form.querySelector(`#${fieldId}`);
        if (field) {
            field.addEventListener('input', () => validateField(field, rules, form));
            field.addEventListener('blur', () => validateField(field, rules, form));
        }
    }
    
    // Validate on submit
    form.addEventListener('submit', function(event) {
        if (!validateForm(form, validationConfig)) {
            event.preventDefault();
        }
    });
};
