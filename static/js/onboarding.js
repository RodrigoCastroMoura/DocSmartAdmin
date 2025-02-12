// Onboarding tutorial configuration
const tutorialSteps = [
    {
        element: '.sidebar',
        title: 'Navigation Menu',
        intro: 'This is your main navigation menu. Here you can access all the key features of the system.',
        position: 'right'
    },
    {
        element: '.search-bar',
        title: 'Search',
        intro: 'Quickly find documents, categories, and other items using the search bar.',
        position: 'bottom'
    },
    {
        element: '.user-menu',
        title: 'User Settings',
        intro: 'Access your profile settings, notifications, and theme preferences here.',
        position: 'left'
    },
    {
        element: '[href="/departments"]',
        title: 'Departments',
        intro: 'Manage your organization\'s departments and their structure.',
        position: 'right'
    },
    {
        element: '[href="/categories"]',
        title: 'Categories',
        intro: 'Organize documents by creating and managing categories.',
        position: 'right'
    },
    {
        element: '[href="/documents"]',
        title: 'Documents',
        intro: 'Upload, view, and manage all your documents in one place.',
        position: 'right'
    },
    {
        element: '.theme-toggle',
        title: 'Theme Switcher',
        intro: 'Switch between light and dark themes for comfortable viewing.',
        position: 'left'
    }
];

function startOnboardingTutorial() {
    const introJs = introJs();
    introJs.setOptions({
        steps: tutorialSteps,
        exitOnOverlayClick: false,
        exitOnEsc: false,
        showStepNumbers: true,
        showBullets: true,
        showProgress: true,
        doneLabel: 'Finish Tutorial',
        nextLabel: 'Next →',
        prevLabel: '← Back'
    });

    introJs.oncomplete(function() {
        // Mark tutorial as completed
        localStorage.setItem('tutorialCompleted', 'true');
        showNotification('Tutorial completed! You can now explore the dashboard.', 'success');
    });

    introJs.start();
}

// Check if tutorial should be shown
function checkAndStartTutorial() {
    const tutorialCompleted = localStorage.getItem('tutorialCompleted');
    const isFirstLogin = !tutorialCompleted;
    
    if (isFirstLogin) {
        startOnboardingTutorial();
    }
}

// Export functions for use in other files
window.startOnboardingTutorial = startOnboardingTutorial;
window.checkAndStartTutorial = checkAndStartTutorial;
