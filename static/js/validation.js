
// Form validation utilities
window.ValidationRules = window.ValidationRules || {
    required: (value) => value && value.trim() !== '' ? '' : 'Campo obrigatório',
    email: (value) => {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(value) ? '' : 'Por favor, digite um endereço de e-mail válido';
    },
    minLength: (length) => (value) => 
        value.length >= length ? '' : `Deve ter pelo menos ${length} caracteres`,
    maxLength: (length) => (value) => 
        value.length <= length ? '' : `Não deve exceder ${length} caracteres`,
    match: (matchId, message) => (value) => {
        const matchElement = document.getElementById(matchId);
        return matchElement.value === value ? '' : message;
    },
    cpf: (value) => {
        const cpfRegex = /^\d{11}$/;
        return cpfRegex.test(value) ? '' : 'Por favor, digite um CPF válido (11 dígitos)';
    },
    phone: (value) => {
        if (!value) return ''; // Phone is optional
        const phoneRegex = /^\d{10,11}$/;
        return phoneRegex.test(value) ? '' : 'Por favor, digite um número de telefone válido';
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
function validateCPF(cpf) {
    cpf = cpf.replace(/[^\d]/g, '');
    
    if (cpf.length !== 11) return false;
    
    // Check for repeated digits
    if (/^(\d)\1{10}$/.test(cpf)) return false;
    
    // Validate check digits
    let sum = 0;
    for (let i = 0; i < 9; i++) {
        sum += parseInt(cpf.charAt(i)) * (10 - i);
    }
    let digit = 11 - (sum % 11);
    if (digit >= 10) digit = 0;
    if (digit !== parseInt(cpf.charAt(9))) return false;
    
    sum = 0;
    for (let i = 0; i < 10; i++) {
        sum += parseInt(cpf.charAt(i)) * (11 - i);
    }
    digit = 11 - (sum % 11);
    if (digit >= 10) digit = 0;
    if (digit !== parseInt(cpf.charAt(10))) return false;
    
    return true;
}
