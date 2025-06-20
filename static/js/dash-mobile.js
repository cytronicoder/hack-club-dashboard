// Mobile Dashboard JavaScript

// Mobile Navigation and PWA
document.addEventListener('DOMContentLoaded', function() {
    // Initialize mobile navigation
    const navTabs = document.querySelectorAll('.nav-tab');
    const sections = document.querySelectorAll('.mobile-section');
    
    navTabs.forEach(tab => {
        tab.addEventListener('click', function() {
            const targetSection = this.dataset.section;
            showMobileSection(targetSection);
            
            // Update active tab
            navTabs.forEach(t => t.classList.remove('active'));
            this.classList.add('active');
        });
    });
    
    // PWA Installation
    initializePWA();
    
    // Load initial data
    loadMobileData();
});

// PWA Installation Logic
function initializePWA() {
    let deferredPrompt;
    const installBanner = document.getElementById('pwa-install-banner');
    const installBtn = document.getElementById('pwa-install-btn-mobile');
    
    // Check if app is already installed
    if (window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone) {
        // App is already installed, don't show banner
        return;
    }
    
    // Show banner after a delay if not dismissed before
    setTimeout(() => {
        if (!localStorage.getItem('pwa-banner-dismissed')) {
            if (installBanner) {
                installBanner.style.display = 'flex';
            }
        }
    }, 3000);
    
    window.addEventListener('beforeinstallprompt', (e) => {
        e.preventDefault();
        deferredPrompt = e;
        
        if (installBanner) {
            installBanner.style.display = 'flex';
        }
    });
    
    if (installBtn) {
        installBtn.addEventListener('click', async () => {
            if (deferredPrompt) {
                deferredPrompt.prompt();
                const { outcome } = await deferredPrompt.userChoice;
                
                if (outcome === 'accepted') {
                    console.log('PWA installed');
                    showToast('App installed successfully!', 'success');
                } else {
                    showToast('App installation cancelled', 'info');
                }
                
                deferredPrompt = null;
                closePWABanner();
            } else {
                // Show manual installation instructions for iOS
                showIOSInstallInstructions();
            }
        });
    }
    
    // Handle install button on the installation page
    const installPageBtn = document.getElementById('pwa-install-btn-page');
    if (installPageBtn) {
        installPageBtn.addEventListener('click', async () => {
            if (deferredPrompt) {
                deferredPrompt.prompt();
                const { outcome } = await deferredPrompt.userChoice;
                
                if (outcome === 'accepted') {
                    console.log('PWA installed');
                    showToast('App installed successfully!', 'success');
                    showMobileSection('dashboard');
                } else {
                    showToast('App installation cancelled', 'info');
                }
                
                deferredPrompt = null;
            } else {
                // Show manual installation instructions for iOS
                showIOSInstallInstructions();
            }
        });
    }
    
    // Handle app installed event
    window.addEventListener('appinstalled', (evt) => {
        console.log('PWA was installed');
        closePWABanner();
        showToast('Welcome to Hack Club Dashboard app!', 'success');
    });
}

function closePWABanner() {
    const banner = document.getElementById('pwa-install-banner');
    if (banner) {
        banner.style.display = 'none';
        localStorage.setItem('pwa-banner-dismissed', 'true');
    }
}

function showIOSInstallInstructions() {
    const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
    const isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
    
    if (isIOS && isSafari) {
        showToast('To install: Tap the Share button, then "Add to Home Screen"', 'info');
    } else {
        showToast('Use Chrome or Safari to install this app', 'info');
    }
}

// Show mobile section
function showMobileSection(sectionName) {
    const sections = document.querySelectorAll('.mobile-section');
    sections.forEach(section => {
        section.classList.remove('active');
    });
    
    const targetSection = document.getElementById(sectionName);
    if (targetSection) {
        targetSection.classList.add('active');
        
        // Load section-specific data
        switch(sectionName) {
            case 'stream':
                loadMobilePosts();
                break;
            case 'assignments':
                loadMobileAssignments();
                break;
            case 'projects':
                // Already handled by existing function
                break;
            case 'resources':
                loadMobileResources();
                break;
            case 'schedule':
                loadMobileMeetings();
                break;
            case 'pizza':
                loadMobileSubmissions();
                break;
        }
    }
    
    // Update nav tabs for detail sections
    if (['assignments', 'projects', 'resources', 'schedule', 'pizza', 'shop', 'ysws', 'settings'].includes(sectionName)) {
        const navTabs = document.querySelectorAll('.nav-tab');
        navTabs.forEach(t => t.classList.remove('active'));
        document.querySelector('.nav-tab[data-section="more"]').classList.add('active');
    }
}

// Load mobile dashboard data
function loadMobileData() {
    // Load stats
    loadMobileStats();
    
    // Load posts if on stream tab
    if (document.getElementById('stream').classList.contains('active')) {
        loadMobilePosts();
    }
}

// Load mobile stats
function loadMobileStats() {
    const clubId = document.querySelector('.mobile-club-dashboard').dataset.clubId;
    
    // Load meetings count
    fetch(`/api/clubs/${clubId}/meetings`)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const count = data.meetings.length;
                const meetingsElement = document.getElementById('meetingsCountMobile');
                if (meetingsElement) meetingsElement.textContent = count;
            }
        })
        .catch(console.error);
    
    // Load assignments count
    fetch(`/api/clubs/${clubId}/assignments`)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const count = data.assignments.length;
                const assignmentsElement = document.getElementById('assignmentsCountMobile');
                if (assignmentsElement) assignmentsElement.textContent = count;
            }
        })
        .catch(console.error);
    
    // Load projects count (placeholder)
    const projectsElement = document.getElementById('projectsCountMobile');
    if (projectsElement) projectsElement.textContent = '0';
}

// Load mobile posts
function loadMobilePosts() {
    const clubId = document.querySelector('.mobile-club-dashboard').dataset.clubId;
    const postsContainer = document.getElementById('postsListMobile');
    
    if (!postsContainer) return;
    
    fetch(`/api/clubs/${clubId}/posts`)
        .then(response => response.json())
        .then(data => {
            if (data.success && data.posts.length > 0) {
                postsContainer.innerHTML = data.posts.map(post => `
                    <div class="mobile-post-card">
                        <div class="post-header-mobile">
                            <div class="post-avatar-mobile">
                                ${post.author_name.charAt(0).toUpperCase()}
                            </div>
                            <div class="post-info-mobile">
                                <div class="post-author">${post.author_name}</div>
                                <div class="post-date">${formatDate(post.created_at)}</div>
                            </div>
                        </div>
                        <div class="post-content-mobile">
                            ${post.content}
                        </div>
                    </div>
                `).join('');
            } else {
                postsContainer.innerHTML = `
                    <div class="empty-state-mobile">
                        <i class="fas fa-stream"></i>
                        <h3>No posts yet</h3>
                        <p>Be the first to share something!</p>
                    </div>
                `;
            }
        })
        .catch(console.error);
}

// Load mobile assignments
function loadMobileAssignments() {
    const clubId = document.querySelector('.mobile-club-dashboard').dataset.clubId;
    const assignmentsContainer = document.getElementById('assignmentsListMobile');
    
    if (!assignmentsContainer) return;
    
    fetch(`/api/clubs/${clubId}/assignments`)
        .then(response => response.json())
        .then(data => {
            if (data.success && data.assignments.length > 0) {
                assignmentsContainer.innerHTML = data.assignments.map(assignment => `
                    <div class="mobile-assignment-card">
                        <div class="assignment-header-mobile">
                            <h4>${assignment.title}</h4>
                            <span class="assignment-status-mobile ${assignment.status}">${assignment.status}</span>
                        </div>
                        <div class="assignment-content-mobile">
                            <p>${assignment.description}</p>
                            ${assignment.due_date ? `<div class="assignment-due">Due: ${formatDate(assignment.due_date)}</div>` : ''}
                        </div>
                    </div>
                `).join('');
            } else {
                assignmentsContainer.innerHTML = `
                    <div class="empty-state-mobile">
                        <i class="fas fa-clipboard-list"></i>
                        <h3>No assignments yet</h3>
                        <p>Create your first assignment to get started!</p>
                    </div>
                `;
            }
        })
        .catch(console.error);
}

// Load mobile resources
function loadMobileResources() {
    const clubId = document.querySelector('.mobile-club-dashboard').dataset.clubId;
    const resourcesContainer = document.getElementById('resourcesListMobile');
    
    if (!resourcesContainer) return;
    
    fetch(`/api/clubs/${clubId}/resources`)
        .then(response => response.json())
        .then(data => {
            if (data.success && data.resources.length > 0) {
                resourcesContainer.innerHTML = data.resources.map(resource => `
                    <div class="mobile-resource-card">
                        <div class="resource-icon-mobile">
                            <i class="fas fa-${resource.icon}"></i>
                        </div>
                        <div class="resource-info-mobile">
                            <h4>${resource.title}</h4>
                            <p>${resource.description}</p>
                            <a href="${resource.url}" target="_blank" class="resource-link">
                                <i class="fas fa-external-link-alt"></i> Visit
                            </a>
                        </div>
                    </div>
                `).join('');
            } else {
                resourcesContainer.innerHTML = `
                    <div class="empty-state-mobile">
                        <i class="fas fa-book"></i>
                        <h3>No resources yet</h3>
                        <p>Add helpful links and materials!</p>
                    </div>
                `;
            }
        })
        .catch(console.error);
}

// Load mobile meetings
function loadMobileMeetings() {
    const clubId = document.querySelector('.mobile-club-dashboard').dataset.clubId;
    const meetingsContainer = document.getElementById('meetingsListMobile');
    
    if (!meetingsContainer) return;
    
    fetch(`/api/clubs/${clubId}/meetings`)
        .then(response => response.json())
        .then(data => {
            if (data.success && data.meetings.length > 0) {
                meetingsContainer.innerHTML = data.meetings.map(meeting => `
                    <div class="mobile-meeting-card">
                        <div class="meeting-header-mobile">
                            <h4>${meeting.title}</h4>
                            <div class="meeting-date">${formatDate(meeting.date)}</div>
                        </div>
                        <div class="meeting-content-mobile">
                            <p>${meeting.description}</p>
                            <div class="meeting-details">
                                <span><i class="fas fa-clock"></i> ${meeting.start_time} - ${meeting.end_time}</span>
                                ${meeting.location ? `<span><i class="fas fa-map-marker-alt"></i> ${meeting.location}</span>` : ''}
                            </div>
                        </div>
                    </div>
                `).join('');
            } else {
                meetingsContainer.innerHTML = `
                    <div class="empty-state-mobile">
                        <i class="fas fa-calendar-times"></i>
                        <h3>No meetings scheduled</h3>
                        <p>Schedule your first meeting!</p>
                    </div>
                `;
            }
        })
        .catch(console.error);
}

// Load mobile submissions
function loadMobileSubmissions() {
    const clubId = document.querySelector('.mobile-club-dashboard').dataset.clubId;
    const submissionsContainer = document.getElementById('clubSubmissionsListMobile');
    
    if (!submissionsContainer) return;
    
    fetch(`/api/clubs/${clubId}/submissions`)
        .then(response => response.json())
        .then(data => {
            if (data.success && data.submissions.length > 0) {
                submissionsContainer.innerHTML = data.submissions.map(submission => `
                    <div class="mobile-submission-card">
                        <div class="submission-header-mobile">
                            <h4>${submission.project_name}</h4>
                            <span class="submission-status-mobile ${submission.status}">${submission.status}</span>
                        </div>
                        <div class="submission-content-mobile">
                            <p>${submission.description}</p>
                            <div class="submission-links">
                                <a href="${submission.github_url}" target="_blank"><i class="fab fa-github"></i> Code</a>
                                <a href="${submission.live_url}" target="_blank"><i class="fas fa-external-link-alt"></i> Live</a>
                            </div>
                        </div>
                    </div>
                `).join('');
            } else {
                submissionsContainer.innerHTML = `
                    <div class="empty-state-mobile">
                        <i class="fas fa-hand-holding-usd"></i>
                        <h3>No submissions yet</h3>
                        <p>Submit your first project!</p>
                    </div>
                `;
            }
        })
        .catch(console.error);
}

// Load Hackatime projects for mobile
function loadHackatimeProjectsMobile() {
    const memberSelect = document.getElementById('hackatimeMemberSelectMobile');
    const projectsContainer = document.getElementById('hackatimeProjectsListMobile');
    
    if (!memberSelect || !projectsContainer) return;
    
    const userId = memberSelect.value;
    if (!userId) {
        projectsContainer.innerHTML = `
            <div class="empty-state-mobile">
                <i class="fas fa-clock"></i>
                <h3>Select a member</h3>
                <p>Choose a member to view their projects</p>
            </div>
        `;
        return;
    }
    
    projectsContainer.innerHTML = `
        <div class="empty-state-mobile">
            <i class="fas fa-spinner fa-spin"></i>
            <h3>Loading projects...</h3>
        </div>
    `;
    
    fetch(`/api/hackatime/projects/${userId}`)
        .then(response => response.json())
        .then(data => {
            if (data.success && data.projects.length > 0) {
                projectsContainer.innerHTML = data.projects.map(project => `
                    <div class="mobile-project-card">
                        <div class="project-header-mobile">
                            <h4>${project.name}</h4>
                            <span class="project-time">${project.total_time}</span>
                        </div>
                        <div class="project-stats-mobile">
                            <span><i class="fas fa-calendar"></i> ${project.last_activity}</span>
                            <span><i class="fas fa-code"></i> ${project.languages.join(', ')}</span>
                        </div>
                    </div>
                `).join('');
            } else {
                projectsContainer.innerHTML = `
                    <div class="empty-state-mobile">
                        <i class="fas fa-clock"></i>
                        <h3>No projects found</h3>
                        <p>This member hasn't tracked any projects yet</p>
                    </div>
                `;
            }
        })
        .catch(error => {
            console.error('Error loading projects:', error);
            projectsContainer.innerHTML = `
                <div class="empty-state-mobile">
                    <i class="fas fa-exclamation-triangle"></i>
                    <h3>Error loading projects</h3>
                    <p>Please try again later</p>
                </div>
            `;
        });
}

// Create post for mobile
function createPost() {
    const content = document.getElementById('postContentMobile')?.value || document.getElementById('postContent')?.value;
    
    if (!content || !content.trim()) {
        showToast('Please enter a message', 'error');
        return;
    }
    
    const clubId = document.querySelector('.mobile-club-dashboard, .club-dashboard').dataset.clubId;
    
    fetch(`/api/clubs/${clubId}/posts`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            content: content.trim()
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Clear the textarea
            if (document.getElementById('postContentMobile')) {
                document.getElementById('postContentMobile').value = '';
            }
            if (document.getElementById('postContent')) {
                document.getElementById('postContent').value = '';
            }
            
            // Reload posts
            loadMobilePosts();
            if (typeof loadPosts === 'function') {
                loadPosts();
            }
            
            showToast('Post created successfully', 'success');
        } else {
            showToast(data.error || 'Failed to create post', 'error');
        }
    })
    .catch(error => {
        console.error('Error creating post:', error);
        showToast('Failed to create post', 'error');
    });
}

// Utility function to format dates
function formatDate(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now - date;
    
    // Less than a day
    if (diff < 24 * 60 * 60 * 1000) {
        return date.toLocaleTimeString('en-US', {
            hour: 'numeric',
            minute: '2-digit',
            hour12: true
        });
    }
    
    // Less than a week
    if (diff < 7 * 24 * 60 * 60 * 1000) {
        return date.toLocaleDateString('en-US', {
            weekday: 'short',
            hour: 'numeric',
            minute: '2-digit',
            hour12: true
        });
    }
    
    // Older
    return date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined
    });
}

// Add mobile-specific CSS for cards
const mobileCardCSS = `
<style>
.mobile-post-card,
.mobile-assignment-card,
.mobile-resource-card,
.mobile-meeting-card,
.mobile-submission-card,
.mobile-project-card {
    background: white;
    border-radius: 16px;
    padding: 1rem;
    margin-bottom: 0.75rem;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
    border: 2px solid #e2e8f0;
    transition: all 0.2s ease;
}

.mobile-post-card:hover,
.mobile-assignment-card:hover,
.mobile-resource-card:hover,
.mobile-meeting-card:hover,
.mobile-submission-card:hover,
.mobile-project-card:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.post-header-mobile,
.assignment-header-mobile,
.meeting-header-mobile,
.submission-header-mobile,
.project-header-mobile {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.75rem;
}

.post-header-mobile {
    align-items: flex-start;
    gap: 0.75rem;
}

.post-avatar-mobile {
    width: 35px;
    height: 35px;
    border-radius: 50%;
    background: #ec3750;
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 600;
    font-size: 0.875rem;
    flex-shrink: 0;
}

.post-info-mobile {
    flex: 1;
}

.post-author {
    font-weight: 600;
    color: #1a202c;
    font-size: 0.875rem;
    margin-bottom: 0.125rem;
}

.post-date {
    font-size: 0.75rem;
    color: #6b7280;
}

.post-content-mobile,
.assignment-content-mobile,
.meeting-content-mobile,
.submission-content-mobile {
    color: #4a5568;
    font-size: 0.875rem;
    line-height: 1.4;
}

.assignment-header-mobile h4,
.meeting-header-mobile h4,
.submission-header-mobile h4,
.project-header-mobile h4 {
    margin: 0;
    font-size: 1rem;
    font-weight: 600;
    color: #1a202c;
    flex: 1;
}

.assignment-status-mobile,
.submission-status-mobile {
    padding: 0.25rem 0.5rem;
    border-radius: 6px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
}

.assignment-status-mobile.active,
.submission-status-mobile.pending {
    background: rgba(59, 130, 246, 0.1);
    color: #3b82f6;
}

.submission-status-mobile.approved {
    background: rgba(16, 185, 129, 0.1);
    color: #10b981;
}

.assignment-due,
.meeting-date {
    font-size: 0.75rem;
    color: #6b7280;
    margin-top: 0.5rem;
}

.meeting-details {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    margin-top: 0.5rem;
}

.meeting-details span {
    font-size: 0.75rem;
    color: #6b7280;
    display: flex;
    align-items: center;
    gap: 0.25rem;
}

.submission-links {
    display: flex;
    gap: 0.75rem;
    margin-top: 0.75rem;
}

.submission-links a {
    color: #ec3750;
    text-decoration: none;
    font-size: 0.8rem;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 0.25rem;
}

.mobile-resource-card {
    display: flex;
    align-items: center;
    gap: 0.75rem;
}

.resource-icon-mobile {
    width: 40px;
    height: 40px;
    background: rgba(236, 55, 80, 0.1);
    color: #ec3750;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.25rem;
    flex-shrink: 0;
}

.resource-info-mobile {
    flex: 1;
}

.resource-info-mobile h4 {
    margin: 0 0 0.25rem 0;
    font-size: 0.9rem;
    font-weight: 600;
    color: #1a202c;
}

.resource-info-mobile p {
    margin: 0 0 0.5rem 0;
    font-size: 0.8rem;
    color: #6b7280;
    line-height: 1.3;
}

.resource-link {
    color: #ec3750;
    text-decoration: none;
    font-size: 0.8rem;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 0.25rem;
}

.project-time {
    font-size: 0.8rem;
    color: #10b981;
    font-weight: 600;
}

.project-stats-mobile {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    margin-top: 0.5rem;
}

.project-stats-mobile span {
    font-size: 0.75rem;
    color: #6b7280;
    display: flex;
    align-items: center;
    gap: 0.25rem;
}
</style>
`;

// Inject mobile card CSS
if (document.head) {
    document.head.insertAdjacentHTML('beforeend', mobileCardCSS);
}