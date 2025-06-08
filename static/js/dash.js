// Global variables
let clubId = '';
let joinCode = '';

// Initialize the application when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('Initializing club dashboard...');

    // Get the club ID and join code from data attributes
    const dashboardElement = document.querySelector('.club-dashboard');
    if (dashboardElement) {
        clubId = dashboardElement.dataset.clubId || '';
        joinCode = dashboardElement.dataset.joinCode || '';
        console.log('Retrieved Club ID:', clubId);
        console.log('Retrieved Join Code:', joinCode);
    }

    // Removed welcome toast since notifications are working

    // Initialize navigation
    initNavigation();

    // Load initial data if club ID exists
    if (clubId) {
        loadInitialData();
    }

    // Setup settings form handler
    setupSettingsForm();
});

// Utility function to safely escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Utility function to create DOM elements safely
function createElement(tag, className = '', textContent = '') {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (textContent) element.textContent = textContent;
    return element;
}

// Initialize navigation - only target sidebar nav links
function initNavigation() {
    console.log('Setting up sidebar navigation...');

    // IMPORTANT: Only target the sidebar navigation links, not the top navbar
    const sidebarNavLinks = document.querySelectorAll('.dashboard-sidebar .nav-link');
    console.log('Found sidebar nav links:', sidebarNavLinks.length);

    sidebarNavLinks.forEach(link => {
        // Remove existing listeners by cloning and replacing
        const newLink = link.cloneNode(true);
        link.parentNode.replaceChild(newLink, link);

        // Add direct onclick property (most reliable method)
        newLink.onclick = function(e) {
            e.preventDefault();
            console.log('Sidebar nav link clicked!'); 
            const section = this.getAttribute('data-section');
            console.log('Section:', section);
            if (section) {
                openTab(section);
                return false; // Prevent default and stop propagation
            }
        };
    });

    // Leave the main navbar links alone - they should navigate to URLs

    // Open default tab or the one from URL hash
    const hash = window.location.hash.substring(1);
    if (hash) {
        openTab(hash);
    } else {
        openTab('dashboard');
    }
}

// Load initial data for the dashboard
function loadInitialData() {
    if (!clubId) return;

    loadPosts();
    loadAssignments();
    loadMeetings();
    loadProjects();
}

// Note: showToast function is provided globally in base.html
// We don't need to redefine it here

function openTab(sectionName) {
    if (!sectionName) return;

    console.log('Opening tab:', sectionName);

    // Get all sections and deactivate them
    const allSections = document.querySelectorAll('.club-section');
    allSections.forEach(section => {
        section.classList.remove('active');
    });

    // Activate the selected section
    const targetSection = document.getElementById(sectionName);
    if (targetSection) {
        targetSection.classList.add('active');
    } else {
        console.warn('Section not found:', sectionName);
        return;
    }

    // Update navigation links
    const allNavLinks = document.querySelectorAll('.nav-link');
    allNavLinks.forEach(link => {
        link.classList.remove('active');
    });

    const activeNavLink = document.querySelector(`.nav-link[data-section="${sectionName}"]`);
    if (activeNavLink) {
        activeNavLink.classList.add('active');
    }

    // Load section data
    loadSectionData(sectionName);
}


function loadSectionData(section) {
    switch(section) {
        case 'stream':
            loadPosts();
            break;
        case 'assignments':
            loadAssignments();
            break;
        case 'schedule':
            loadMeetings();
            break;
        case 'projects':
            loadProjects();
            break;
        case 'resources':
            loadResources();
            break;
        case 'pizza':
            loadClubPizzaGrants();
            break;
        case 'shop':
            loadShop();
            break;
    }
}

function showQRModal() {
    if (!joinCode) {
        showToast('error', 'Join code is not available to generate QR code.', 'Error');
        console.error('Join code is undefined, cannot generate QR code.');
        return;
    }
    const joinUrl = `${window.location.origin}/join-club?code=${joinCode}`;
    const joinUrlInput = document.getElementById('joinUrl');
    if (joinUrlInput) {
        joinUrlInput.value = joinUrl;
    } else {
        console.warn('joinUrl input element not found in QR modal.');
    }

    const qrContainer = document.getElementById('qrcode');
    if (!qrContainer) {
        console.error('QR code container not found');
        return;
    }

    qrContainer.innerHTML = '';

    const canvas = document.createElement('canvas');
    qrContainer.appendChild(canvas);

    QRCode.toCanvas(canvas, joinUrl, {
        width: 200,
        margin: 2,
        color: {
            dark: '#ec3750',
            light: '#ffffff'
        }
    }, function (error) {
        if (error) {
            console.error('QR Code generation failed:', error);
            qrContainer.innerHTML = '<p style="color: #ef4444;">Failed to generate QR code</p>';
        }
    });

    const modal = document.getElementById('qrModal');
    if (modal) {
        modal.style.display = 'block';
    }
}

function copyJoinUrl() {
    const joinUrl = document.getElementById('joinUrl');
    joinUrl.select();
    document.execCommand('copy');
    showToast('success', 'Join code copied to clipboard!', 'Copied');
}

function generateNewJoinCode() {
    if (!clubId) {
        showToast('error', 'Cannot generate new join code: Club ID is missing.', 'Error');
        console.error('generateNewJoinCode: clubId is missing.');
        return;
    }
    showConfirmModal(
        'Generate a new join code?',
        'The old code will stop working.',
        () => {
            fetch(`/api/clubs/${clubId}/join-code`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.join_code) {
                    const joinCodeDisplay = document.querySelector('.join-code-display');
                    if (joinCodeDisplay) {
                        joinCodeDisplay.innerHTML = '';
                        const icon = createElement('i', 'fas fa-key');
                        joinCodeDisplay.appendChild(icon);
                        joinCodeDisplay.appendChild(document.createTextNode(' ' + data.join_code));
                    }
                    showToast('success', 'New join code generated!', 'Generated');
                } else {
                    showToast('error', 'Failed to generate new join code', 'Error');
                }
            })
            .catch(error => {
                showToast('error', 'Error generating join code', 'Error');
            });
        }
    );
}

function showConfirmModal(message, details, onConfirm) {
    const confirmMessage = document.getElementById('confirmMessage');
    if (confirmMessage) {
        confirmMessage.innerHTML = '';
        confirmMessage.appendChild(document.createTextNode(message));
        if (details) {
            confirmMessage.appendChild(createElement('br'));
            const small = createElement('small', '', details);
            confirmMessage.appendChild(small);
        }
    }
    document.getElementById('confirmModal').style.display = 'block';

    document.getElementById('confirmButton').onclick = () => {
        document.getElementById('confirmModal').style.display = 'none';
        onConfirm();
    };
}

function loadPosts() {
    if (!clubId) {
        console.warn('loadPosts: clubId is missing. Skipping fetch.');
        const postsList = document.getElementById('postsList');
        if (postsList) postsList.textContent = 'Error: Club information is unavailable to load posts.';
        return;
    }
    fetch(`/api/clubs/${clubId}/posts`)
        .then(response => response.json())
        .then(data => {
            const postsList = document.getElementById('postsList');
            postsList.innerHTML = '';

            if (data.posts && data.posts.length > 0) {
                data.posts.forEach(post => {
                    const postCard = createElement('div', 'post-card');

                    const postHeader = createElement('div', 'post-header');
                    const postAvatar = createElement('div', 'post-avatar', post.user.username[0].toUpperCase());
                    const postInfo = createElement('div', 'post-info');
                    const postUsername = createElement('h4', '', post.user.username);
                    const postDate = createElement('div', 'post-date', new Date(post.created_at).toLocaleDateString());

                    postInfo.appendChild(postUsername);
                    postInfo.appendChild(postDate);
                    postHeader.appendChild(postAvatar);
                    postHeader.appendChild(postInfo);

                    const postContent = createElement('div', 'post-content');
                    const postText = createElement('p', '', post.content);
                    postContent.appendChild(postText);

                    postCard.appendChild(postHeader);
                    postCard.appendChild(postContent);
                    postsList.appendChild(postCard);
                });
            } else {
                const emptyState = createElement('div', 'empty-state');
                const icon = createElement('i', 'fas fa-stream');
                const title = createElement('h3', '', 'No posts yet');
                const description = createElement('p', '', 'Be the first to share something with your club!');

                emptyState.appendChild(icon);
                emptyState.appendChild(title);
                emptyState.appendChild(description);
                postsList.appendChild(emptyState);
            }
        })
        .catch(error => {
            showToast('error', 'Failed to load posts', 'Error');
        });
}

function createPost() {
    if (!clubId) {
        showToast('error', 'Cannot create post: Club ID is missing.', 'Error');
        console.error('createPost: clubId is missing.');
        return;
    }
    const content = document.getElementById('postContent').value;
    if (!content.trim()) {
        showToast('error', 'Please enter some content', 'Validation Error');
        return;
    }

    fetch(`/api/clubs/${clubId}/posts`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ content })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            document.getElementById('postContent').value = '';
            loadPosts();
            showToast('success', 'Post created successfully', 'Post Created');
        } else {
            showToast('error', data.error || 'Failed to create post', 'Error');
        }
    })
    .catch(error => {
        showToast('error', 'Error creating post', 'Error');
    });
}

function openCreateAssignmentModal() {
    const modal = document.getElementById('createAssignmentModal');
    if (modal) modal.style.display = 'block';
}

function createAssignment() {
    if (!clubId) {
        showToast('error', 'Cannot create assignment: Club ID is missing.', 'Error');
        console.error('createAssignment: clubId is missing.');
        return;
    }
    const title = document.getElementById('assignmentTitle').value;
    const description = document.getElementById('assignmentDescription').value;
    const dueDate = document.getElementById('assignmentDueDate').value;
    const forAllMembers = document.getElementById('assignmentForAll').checked;

    if (!title || !description) {
        showToast('error', 'Please fill in all required fields', 'Validation Error');
        return;
    }

    fetch(`/api/clubs/${clubId}/assignments`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            title,
            description,
            due_date: dueDate || null,
            for_all_members: forAllMembers
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            document.getElementById('createAssignmentModal').style.display = 'none';
            document.getElementById('createAssignmentForm').reset();
            loadAssignments();
            showToast('success', 'Assignment created successfully', 'Assignment Created');
        } else {
            showToast('error', data.error || 'Failed to create assignment', 'Error');
        }
    })
    .catch(error => {
        showToast('error', 'Error creating assignment', 'Error');
    });
}

function loadAssignments() {
    if (!clubId) {
        console.warn('loadAssignments: clubId is missing. Skipping fetch.');
        const assignmentsList = document.getElementById('assignmentsList');
        if (assignmentsList) assignmentsList.textContent = 'Error: Club information is unavailable to load assignments.';
        return;
    }
    fetch(`/api/clubs/${clubId}/assignments`)
        .then(response => response.json())
        .then(data => {
            const assignmentsList = document.getElementById('assignmentsList');
            const assignmentsCount = document.getElementById('assignmentsCount');

            assignmentsList.innerHTML = '';

            if (data.assignments && data.assignments.length > 0) {
                data.assignments.forEach(assignment => {
                    const card = createElement('div', 'card');
                    card.style.marginBottom = '1rem';

                    const cardHeader = createElement('div', 'card-header');
                    cardHeader.style.cssText = 'display: flex; justify-content: space-between; align-items: flex-start;';

                    const headerDiv = createElement('div');
                    const title = createElement('h3', '', assignment.title);
                    title.style.cssText = 'margin: 0; font-size: 1.125rem; color: #1f2937;';

                    const statusSpan = createElement('span', '', assignment.status);
                    statusSpan.style.cssText = `background: ${assignment.status === 'active' ? '#10b981' : '#6b7280'}; color: white; padding: 0.25rem 0.5rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; margin-top: 0.5rem; display: inline-block;`;

                    headerDiv.appendChild(title);
                    headerDiv.appendChild(statusSpan);
                    cardHeader.appendChild(headerDiv);

                    const cardBody = createElement('div', 'card-body');
                    const description = createElement('p', '', assignment.description);
                    description.style.cssText = 'margin-bottom: 1rem; color: #6b7280;';
                    cardBody.appendChild(description);

                    const infoDiv = createElement('div');
                    infoDiv.style.cssText = 'display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.875rem; color: #6b7280;';

                    if (assignment.due_date) {
                        const dueSpan = createElement('span');
                        dueSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                        const dueIcon = createElement('i', 'fas fa-calendar');
                        dueSpan.appendChild(dueIcon);
                        dueSpan.appendChild(document.createTextNode(' Due: ' + new Date(assignment.due_date).toLocaleDateString()));
                        infoDiv.appendChild(dueSpan);
                    }

                    const membersSpan = createElement('span');
                    membersSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                    const membersIcon = createElement('i', 'fas fa-users');
                    membersSpan.appendChild(membersIcon);
                    membersSpan.appendChild(document.createTextNode(' ' + (assignment.for_all_members ? 'All members' : 'Selected members')));
                    infoDiv.appendChild(membersSpan);

                    cardBody.appendChild(infoDiv);
                    card.appendChild(cardHeader);
                    card.appendChild(cardBody);
                    assignmentsList.appendChild(card);
                });

                assignmentsCount.textContent = data.assignments.filter(a => a.status === 'active').length;
            } else {
                const emptyState = createElement('div', 'empty-state');
                const icon = createElement('i', 'fas fa-clipboard-list');
                const title = createElement('h3', '', 'No assignments yet');
                const description = createElement('p', '', 'Create your first assignment to get started!');

                emptyState.appendChild(icon);
                emptyState.appendChild(title);
                emptyState.appendChild(description);
                assignmentsList.appendChild(emptyState);

                assignmentsCount.textContent = '0';
            }
        })
        .catch(error => {
            showToast('error', 'Failed to load assignments', 'Error');
        });
}

// Opening the create meeting modal
function openCreateMeetingModal() {
    // Close edit modal if it's open
    if (typeof closeEditMeetingModal === 'function') {
        closeEditMeetingModal();
    }

    // Clear form fields
    const form = document.getElementById('createMeetingForm');
    if (form) form.reset();

    // Show the modal
    const modal = document.getElementById('createMeetingModal');
    if (modal) modal.style.display = 'block';
}

function createMeeting() {
    if (!clubId) {
        showToast('error', 'Cannot create meeting: Club ID is missing.', 'Error');
        console.error('createMeeting: clubId is missing.');
        return;
    }
    const title = document.getElementById('meetingTitle').value;
    const description = document.getElementById('meetingDescription').value;
    const date = document.getElementById('meetingDate').value;
    const startTime = document.getElementById('meetingStartTime').value;
    const endTime = document.getElementById('meetingEndTime').value;
    const location = document.getElementById('meetingLocation').value;
    const link = document.getElementById('meetingLink').value;

    if (!title || !date || !startTime) {
        showToast('error', 'Please fill in all required fields', 'Validation Error');
        return;
    }

    fetch(`/api/clubs/${clubId}/meetings`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            title,
            description,
            meeting_date: date,
            start_time: startTime,
            end_time: endTime,
            location,
            meeting_link: link
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            document.getElementById('createMeetingModal').style.display = 'none';
            document.getElementById('createMeetingForm').reset();
            loadMeetings();
            showToast('success', 'Meeting scheduled successfully', 'Meeting Scheduled');
        } else {
            showToast('error', data.error || 'Failed to schedule meeting', 'Error');
        }
    })
    .catch(error => {
        showToast('error', 'Error scheduling meeting', 'Error');
    });
}

function loadMeetings() {
    if (!clubId) {
        console.warn('loadMeetings: clubId is missing. Skipping fetch.');
        const meetingsList = document.getElementById('meetingsList');
        if (meetingsList) meetingsList.textContent = 'Error: Club information is unavailable to load meetings.';
        return;
    }
    fetch(`/api/clubs/${clubId}/meetings`)
        .then(response => response.json())
        .then(data => {
            const meetingsList = document.getElementById('meetingsList');
            const meetingsCount = document.getElementById('meetingsCount');

            meetingsList.innerHTML = '';

            if (data.meetings && data.meetings.length > 0) {
                data.meetings.forEach(meeting => {
                    const card = createElement('div', 'card');
                    card.style.marginBottom = '1rem';
                    card.id = `meeting-${meeting.id}`;

                    const cardHeader = createElement('div', 'card-header');
                    cardHeader.style.cssText = 'display: flex; justify-content: space-between; align-items: flex-start;';

                    const headerDiv = createElement('div');
                    const title = createElement('h3', '', meeting.title);
                    title.style.cssText = 'margin: 0; font-size: 1.125rem; color: #1f2937;';
                    headerDiv.appendChild(title);
                    cardHeader.appendChild(headerDiv);

                    const cardBody = createElement('div', 'card-body');

                    if (meeting.description) {
                        const description = createElement('p', '', meeting.description);
                        description.style.cssText = 'margin-bottom: 1rem; color: #6b7280;';
                        cardBody.appendChild(description);
                    }

                    const infoDiv = createElement('div');
                    infoDiv.style.cssText = 'display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.875rem; color: #6b7280;';

                    const dateSpan = createElement('span');
                    dateSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                    const dateIcon = createElement('i', 'fas fa-calendar');
                    dateSpan.appendChild(dateIcon);
                    dateSpan.appendChild(document.createTextNode(' ' + new Date(meeting.meeting_date).toLocaleDateString()));
                    infoDiv.appendChild(dateSpan);

                    const timeSpan = createElement('span');
                    timeSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                    const timeIcon = createElement('i', 'fas fa-clock');
                    timeSpan.appendChild(timeIcon);
                    const timeText = meeting.start_time + (meeting.end_time ? ` - ${meeting.end_time}` : '');
                    timeSpan.appendChild(document.createTextNode(' ' + timeText));
                    infoDiv.appendChild(timeSpan);

                    if (meeting.location) {
                        const locationSpan = createElement('span');
                        locationSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                        const locationIcon = createElement('i', 'fas fa-map-marker-alt');
                        locationSpan.appendChild(locationIcon);
                        locationSpan.appendChild(document.createTextNode(' ' + meeting.location));
                        infoDiv.appendChild(locationSpan);
                    }

                    if (meeting.meeting_link) {
                        const linkSpan = createElement('span');
                        linkSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                        const linkIcon = createElement('i', 'fas fa-link');
                        linkSpan.appendChild(linkIcon);
                        linkSpan.appendChild(document.createTextNode(' '));

                        const link = createElement('a');
                        link.href = meeting.meeting_link;
                        link.target = '_blank';
                        link.style.color = '#ec3750';
                        link.textContent = 'Visit Resource';
                        linkSpan.appendChild(link);
                        infoDiv.appendChild(linkSpan);
                    }

                    cardBody.appendChild(infoDiv);
                    card.appendChild(cardHeader);
                    card.appendChild(cardBody);
                    meetingsList.appendChild(card);
                });

                const thisMonth = new Date().getMonth();
                const thisYear = new Date().getFullYear();
                const thisMonthMeetings = data.meetings.filter(m => {
                    const meetingDate = new Date(m.meeting_date);
                    return meetingDate.getMonth() === thisMonth && meetingDate.getFullYear() === thisYear;
                });
                meetingsCount.textContent = thisMonthMeetings.length;
            } else {
                const emptyState = createElement('div', 'empty-state');
                const icon = createElement('i', 'fas fa-calendar-times');
                const title = createElement('h3', '', 'No meetings scheduled');
                const description = createElement('p', '', 'Schedule your first club meeting to get started!');

                emptyState.appendChild(icon);
                emptyState.appendChild(title);
                emptyState.appendChild(description);
                meetingsList.appendChild(emptyState);

                meetingsCount.textContent = '0';
            }
        })
        .catch(error => {
            showToast('error', 'Failed to load meetings', 'Error');
        });
}

function editMeeting(id, title, description, date, startTime, endTime, location, link) {
    // Populate edit form
    document.getElementById('meetingTitle').value = title;
    document.getElementById('meetingDescription').value = description;
    document.getElementById('meetingDate').value = date;
    document.getElementById('meetingStartTime').value = startTime;
    document.getElementById('meetingEndTime').value = endTime;
    document.getElementById('meetingLocation').value = location;
    document.getElementById('meetingLink').value = link;

    // Change form action to update
    document.getElementById('createMeetingModal').setAttribute('data-edit-id', id);
    document.querySelector('#createMeetingModal .modal-header h3').textContent = 'Edit Meeting';
    const submitBtn = document.querySelector('#createMeetingModal .btn-primary');
    submitBtn.textContent = '';
    const icon = createElement('i', 'fas fa-save');
    submitBtn.appendChild(icon);
    submitBtn.appendChild(document.createTextNode(' Update Meeting'));
    submitBtn.setAttribute('onclick', 'updateMeeting()');

    const modal = document.getElementById('createMeetingModal');
    if (modal) modal.style.display = 'block';
}

function updateMeeting() {
    const id = document.getElementById('createMeetingModal').getAttribute('data-edit-id');
    const title = document.getElementById('meetingTitle').value;
    const description = document.getElementById('meetingDescription').value;
    const date = document.getElementById('meetingDate').value;
    const startTime = document.getElementById('meetingStartTime').value;
    const endTime = document.getElementById('meetingEndTime').value;
    const location = document.getElementById('meetingLocation').value;
    const link = document.getElementById('meetingLink').value;

    if (!title || !date || !startTime) {
        showToast('error', 'Please fill in all required fields', 'Validation Error');
        return;
    }

    fetch(`/api/clubs/${clubId}/meetings/${id}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            title,
            description,
            meeting_date: date,
            start_time: startTime,
            end_time: endTime,
            location,
            meeting_link: link
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            closeEditMeetingModal();
            loadMeetings();
            showToast('success', 'Meeting updated successfully', 'Meeting Updated');
        } else {
            showToast('error', data.error || 'Failed to update meeting', 'Error');
        }
    })
    .catch(error => {
        showToast('error', 'Error updating meeting', 'Error');
    });
}

function deleteMeeting(id, title) {
    showConfirmModal(
        `Delete "${title}"?`,
        'This action cannot be undone.',
        () => {
            fetch(`/api/clubs/${clubId}/meetings/${id}`, {
                method: 'DELETE'
            })
            .then(response => response.json())
            .then(data => {
                if (data.message) {
                    loadMeetings();
                    showToast('success', 'Meeting deleted successfully', 'Meeting Deleted');
                } else {
                    showToast('error', data.error || 'Failed to delete meeting', 'Error');
                }
            })
            .catch(error => {
                showToast('error', 'Error deleting meeting', 'Error');
            });
        }
    );
}

function closeEditMeetingModal() {
    const modal = document.getElementById('createMeetingModal');
    if (modal){
        modal.style.display = 'none';
        modal.removeAttribute('data-edit-id');
    }
    document.querySelector('#createMeetingModal .modal-header h3').textContent = 'Schedule Meeting';
    const submitBtn = document.querySelector('#createMeetingModal .btn-primary');
    submitBtn.textContent = '';
    const icon = createElement('i', 'fas fa-calendar-plus');
    submitBtn.appendChild(icon);
    submitBtn.appendChild(document.createTextNode(' Schedule Meeting'));
    submitBtn.setAttribute('onclick', 'createMeeting()');
    document.getElementById('createMeetingForm').reset();
}

// This comment is kept to maintain line numbers, but the duplicate function has been removed

function loadProjects() {
    if (!clubId) {
        console.warn('loadProjects: clubId is missing. Skipping fetch.');
        const projectsList = document.getElementById('projects-list'); // Ensure this ID matches your HTML
        if (projectsList) projectsList.textContent = 'Error: Club information is unavailable to load projects.';
        return;
    }
    fetch(`/api/clubs/${clubId}/projects`)
        .then(response => response.json())
        .then(data => {
            const projectsList = document.getElementById('projectsList');
            const projectsCount = document.getElementById('projectsCount');

            projectsList.innerHTML = '';

            if (data.projects && data.projects.length > 0) {
                data.projects.forEach(project => {
                    const card = createElement('div', 'card');
                    card.style.marginBottom = '1rem';

                    const cardHeader = createElement('div', 'card-header');
                    cardHeader.style.cssText = 'display: flex; justify-content: space-between; align-items: flex-start;';

                    const headerDiv = createElement('div');
                    const title = createElement('h3', '', project.name);
                    title.style.cssText = 'margin: 0; font-size: 1.125rem; color: #1f2937;';
                    headerDiv.appendChild(title);

                    if (project.featured) {
                        const featuredSpan = createElement('span', '', 'Featured');
                        featuredSpan.style.cssText = 'background: #f59e0b; color: white; padding: 0.25rem 0.5rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; margin-top: 0.5rem; display: inline-block;';
                        headerDiv.appendChild(featuredSpan);
                    }

                    cardHeader.appendChild(headerDiv);

                    const cardBody = createElement('div', 'card-body');
                    const description = createElement('p', '', project.description || 'No description available');
                    description.style.cssText = 'margin-bottom: 1rem; color: #6b7280;';
                    cardBody.appendChild(description);

                    const infoDiv = createElement('div');
                    infoDiv.style.cssText = 'display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.875rem; color: #6b7280;';

                    const ownerSpan = createElement('span');
                    ownerSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                    const ownerIcon = createElement('i', 'fas fa-user');
                    ownerSpan.appendChild(ownerIcon);
                    ownerSpan.appendChild(document.createTextNode(' ' + project.owner.username));
                    infoDiv.appendChild(ownerSpan);

                    const dateSpan = createElement('span');
                    dateSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                    const dateIcon = createElement('i', 'fas fa-calendar');
                    dateSpan.appendChild(dateIcon);
                    dateSpan.appendChild(document.createTextNode(' ' + new Date(project.updated_at).toLocaleDateString()));
                    infoDiv.appendChild(dateSpan);

                    cardBody.appendChild(infoDiv);
                    card.appendChild(cardHeader);
                    card.appendChild(cardBody);
                    projectsList.appendChild(card);
                });

                projectsCount.textContent = data.projects.length;
            } else {
                const emptyState = createElement('div', 'empty-state');
                const icon = createElement('i', 'fas fa-code');
                const title = createElement('h3', '', 'No projects yet');
                const description = createElement('p', '', 'Members can start creating projects to showcase here!');

                emptyState.appendChild(icon);
                emptyState.appendChild(title);
                emptyState.appendChild(description);
                projectsList.appendChild(emptyState);

                projectsCount.textContent = '0';
            }
        })
        .catch(error => {
            showToast('error', 'Failed to load projects', 'Error');
        });
}

// Opening the add resource modal
function openAddResourceModal() {
    // Close edit modal if it's open
    if (typeof closeEditResourceModal === 'function') {
        closeEditResourceModal();
    }

    // Clear form fields
    const form = document.getElementById('addResourceForm');
    if (form) form.reset();

    // Show the modal
    const modal = document.getElementById('addResourceModal');
    if (modal) modal.style.display = 'block';
}

function addResource() {
    if (!clubId) {
        showToast('error', 'Cannot add resource: Club ID is missing.', 'Error');
        console.error('addResource: clubId is missing.');
        return;
    }
    const title = document.getElementById('resourceTitle').value;
    const url = document.getElementById('resourceUrl').value;
    const description = document.getElementById('resourceDescription').value;
    const icon = document.getElementById('resourceIcon').value;

    if (!title || !url) {
        showToast('error', 'Please fill in title and URL', 'Validation Error');
        return;
    }

    fetch(`/api/clubs/${clubId}/resources`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            title,
            url,
            description,
            icon
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            document.getElementById('addResourceModal').style.display = 'none';
            document.getElementById('addResourceForm').reset();
            loadResources();
            showToast('success', 'Resource added successfully', 'Resource Added');
        } else {
            showToast('error', data.error || 'Failed to add resource', 'Error');
        }
    })
    .catch(error => {
        showToast('error', 'Error adding resource', 'Error');
    });
}

function loadResources() {
    if (!clubId) {
        console.warn('loadResources: clubId is missing. Skipping fetch.');
        const resourcesList = document.getElementById('resourcesList');
        if (resourcesList) resourcesList.textContent = 'Error: Club information is unavailable to load resources.';
        return;
    }
    fetch(`/api/clubs/${clubId}/resources`)
        .then(response => response.json())
        .then(data => {
            const resourcesList = document.getElementById('resourcesList');
            resourcesList.innerHTML = '';

            if (data.resources && data.resources.length > 0) {
                data.resources.forEach(resource => {
                    const card = createElement('div', 'card');
                    card.style.marginBottom = '1rem';
                    card.id = `resource-${resource.id}`;

                    const cardHeader = createElement('div', 'card-header');
                    cardHeader.style.cssText = 'display: flex; justify-content: space-between; align-items: flex-start;';

                    const headerDiv = createElement('div');
                    const title = createElement('h3');
                    title.style.cssText = 'margin: 0; font-size: 1.125rem; color: #1f2937;';
                    const icon = createElement('i', `fas fa-${resource.icon}`);
                    title.appendChild(icon);
                    title.appendChild(document.createTextNode(' ' + resource.title));
                    headerDiv.appendChild(title);
                    cardHeader.appendChild(headerDiv);

                    const cardBody = createElement('div', 'card-body');

                    if (resource.description) {
                        const description = createElement('p', '', resource.description);
                        description.style.cssText = 'margin-bottom: 1rem; color: #6b7280;';
                        cardBody.appendChild(description);
                    }

                    const infoDiv = createElement('div');
                    infoDiv.style.cssText = 'display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.875rem; color: #6b7280;';

                    const linkSpan = createElement('span');
                    linkSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                    const linkIcon = createElement('i', 'fas fa-link');
                    linkSpan.appendChild(linkIcon);
                    linkSpan.appendChild(document.createTextNode(' '));

                    const link = createElement('a');
                    link.href = resource.url;
                    link.target = '_blank';
                    link.style.color = '#ec3750';
                    link.textContent = 'Visit Resource';
                    linkSpan.appendChild(link);
                    infoDiv.appendChild(linkSpan);

                    cardBody.appendChild(infoDiv);
                    card.appendChild(cardHeader);
                    card.appendChild(cardBody);
                    resourcesList.appendChild(card);
                });
            } else {
                const emptyState = createElement('div', 'empty-state');
                const icon = createElement('i', 'fas fa-book');
                const title = createElement('h3', '', 'No resources yet');
                const description = createElement('p', '', 'Add helpful links and learning materials for your club!');

                emptyState.appendChild(icon);
                emptyState.appendChild(title);
                emptyState.appendChild(description);
                resourcesList.appendChild(emptyState);
            }
        })
        .catch(error => {
            showToast('error', 'Failed to load resources', 'Error');
        });
}

function editResource(id, title, url, description, icon) {
    // Populate edit form
    document.getElementById('resourceTitle').value = title;
    document.getElementById('resourceUrl').value = url;
    document.getElementById('resourceDescription').value = description;
    document.getElementById('resourceIcon').value = icon;

    // Change form action to update
    document.getElementById('addResourceModal').setAttribute('data-edit-id', id);
    document.querySelector('#addResourceModal .modal-header h3').textContent = 'Edit Resource';
    const submitBtn = document.querySelector('#addResourceModal .btn-primary');
    submitBtn.textContent = '';
    const saveIcon = createElement('i', 'fas fa-save');
    submitBtn.appendChild(saveIcon);
    submitBtn.appendChild(document.createTextNode(' Update Resource'));
    submitBtn.setAttribute('onclick', 'updateResource()');
    const modal = document.getElementById('addResourceModal');
    if (modal) modal.style.display = 'block';
}

function updateResource() {
    const id = document.getElementById('addResourceModal').getAttribute('data-edit-id');
    const title = document.getElementById('resourceTitle').value;
    const url = document.getElementById('resourceUrl').value;
    const description = document.getElementById('resourceDescription').value;
    const icon = document.getElementById('resourceIcon').value;

    if (!title || !url) {
        showToast('error', 'Please fill in title and URL', 'Validation Error');
        return;
    }

    fetch(`/api/clubs/${clubId}/resources/${id}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            title,
            url,
            description,
            icon
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            closeEditResourceModal();
            loadResources();
            showToast('success', 'Resource updated successfully', 'Resource Updated');
        } else {
            showToast('error', data.error || 'Failed to update resource', 'Error');
        }
    })
    .catch(error => {
        showToast('error', 'Error updating resource', 'Error');
    });
}

function deleteResource(id, title) {
    showConfirmModal(
        `Delete "${title}"?`,
        'This action cannot be undone.',
        () => {
            fetch(`/api/clubs/${clubId}/resources/${id}`, {
                method: 'DELETE'
            })
            .then(response => response.json())
            .then(data => {
                if (data.message) {
                    loadResources();showToast('success', 'Resource deleted successfully', 'Resource Deleted');
                } else {
                    showToast('error', data.error || 'Failed to delete resource', 'Error');
                }
            })
            .catch(error => {
                showToast('error', 'Error deleting resource', 'Error');
            });
        }
    );
}

function closeEditResourceModal() {
    const modal = document.getElementById('addResourceModal');
    if(modal){
        modal.style.display = 'none';
        modal.removeAttribute('data-edit-id');
    }
    document.querySelector('#addResourceModal .modal-header h3').textContent = 'Add Resource';
    const submitBtn = document.querySelector('#addResourceModal .btn-primary');
    submitBtn.textContent = '';
    const addIcon = createElement('i', 'fas fa-plus');
    submitBtn.appendChild(addIcon);
    submitBtn.appendChild(document.createTextNode(' Add Resource'));
    submitBtn.setAttribute('onclick', 'addResource()');
    document.getElementById('addResourceForm').reset();
}

// This comment is kept to maintain line numbers, but the duplicate function has been removed

// Pizza Grant functionality
function openPizzaGrantModal() {
    const modal = document.getElementById('pizzaGrantModal');
    if (modal) {
        modal.style.display = 'block';
        // Auto-fill user data
        loadMemberData(document.getElementById('grantMemberSelect').value);
        loadMemberHackatimeProjects();
    }
}

function loadMemberData(userId) {
    if (!userId) {
        // Clear all fields if no user selected
        document.getElementById('grantFirstName').value = '';
        document.getElementById('grantLastName').value = '';
        document.getElementById('grantEmail').value = '';
        document.getElementById('grantBirthday').value = '';
        return;
    }

    // Fetch user data from API
    fetch(`/api/user/${userId}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                // Clear fields if error
                document.getElementById('grantFirstName').value = '';
                document.getElementById('grantLastName').value = '';
                document.getElementById('grantEmail').value = '';
                document.getElementById('grantBirthday').value = '';
            } else {
                // Populate fields with user data
                document.getElementById('grantFirstName').value = data.first_name || '';
                document.getElementById('grantLastName').value = data.last_name || '';
                document.getElementById('grantEmail').value = data.email || '';
                document.getElementById('grantBirthday').value = data.birthday || '';
            }
        })
        .catch(error => {
            console.error('Error loading user data:', error);
            // Clear fields on error
            document.getElementById('grantFirstName').value = '';
            document.getElementById('grantLastName').value = '';
            document.getElementById('grantEmail').value = '';
            document.getElementById('grantBirthday').value = '';
        });
}

function loadMemberHackatimeProjects() {
    const userId = document.getElementById('grantMemberSelect').value;
    const projectSelect = document.getElementById('grantProjectSelect');

    if (!userId) {
        projectSelect.innerHTML = '<option value="">Select your project</option>';
        return;
    }

    projectSelect.innerHTML = '<option value="">Loading projects...</option>';

    fetch(`/api/hackatime/projects/${userId}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                projectSelect.innerHTML = '<option value="">No Hackatime projects found</option>';
                return;
            }

            projectSelect.innerHTML = '<option value="">Select your project</option>';

            if (data.projects && data.projects.length > 0) {
                data.projects.forEach(project => {
                    const option = document.createElement('option');
                    option.value = JSON.stringify({
                        name: project.name,
                        total_seconds: project.total_seconds,
                        formatted_time: project.formatted_time
                    });
                    option.textContent = `${project.name} (${project.formatted_time})`;
                    projectSelect.appendChild(option);
                });
            } else {
                projectSelect.innerHTML = '<option value="">No projects found</option>';
            }
        })
        .catch(error => {
            projectSelect.innerHTML = '<option value="">Error loading projects</option>';
        });
}

function updateGrantAmount() {
    // This function was referenced in HTML but not defined
    // Since we removed grant amount display, this is now a no-op
    console.log('Grant amount calculation removed as requested');
}


function submitPizzaGrant() {
    const projectSelect = document.getElementById('grantProjectSelect');
    let projectData = null;

    if (projectSelect.value) {
        try {
            projectData = JSON.parse(projectSelect.value);
        } catch (e) {
            showToast('error', 'Invalid project selection', 'Validation Error');
            return;
        }
    }

    // Handle screenshot upload first
    const screenshotFile = document.getElementById('grantScreenshot').files[0];
    if (!screenshotFile) {
        showToast('error', 'Please upload a screenshot', 'Validation Error');
        return;
    }

    // Show loading state
    const submitButton = document.querySelector('#pizzaGrantModal .btn-primary');
    const originalText = submitButton.textContent;
    submitButton.textContent = '';
    const spinner = createElement('i', 'fas fa-spinner fa-spin');
    submitButton.appendChild(spinner);
    submitButton.appendChild(document.createTextNode(' Uploading...'));
    submitButton.disabled = true;

    // Upload screenshot to CDN first
    const formData = new FormData();
    formData.append('screenshot', screenshotFile);

    fetch('/api/upload-screenshot', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(uploadData => {
        if (!uploadData.success) {
            throw new Error(uploadData.error || 'Failed to upload screenshot');
        }

        // Now submit the pizza grant with the CDN URL
        submitPizzaGrantWithScreenshot(uploadData.url, projectData, submitButton, originalText);
    })
    .catch(error => {
        submitButton.textContent = originalText;
        submitButton.disabled = false;
        showToast('error', error.message || 'Error uploading screenshot', 'Upload Error');
    });
}

function submitPizzaGrantWithScreenshot(screenshotUrl, projectData, submitButton, originalText) {

    const formData = {
        member_id: document.getElementById('grantMemberSelect').value,
        project_name: projectData ? projectData.name : document.getElementById('grantProjectSelect').selectedOptions[0]?.text || '',
        project_hours: projectData ? (projectData.total_seconds / 3600).toFixed(2) : '0',
        first_name: document.getElementById('grantFirstName').value,
        last_name: document.getElementById('grantLastName').value,
        email: document.getElementById('grantEmail').value,
        birthday: document.getElementById('grantBirthday').value,
        project_description: document.getElementById('grantDescription').value,
        github_url: document.getElementById('grantGithubUrl').value,
        live_url: document.getElementById('grantLiveUrl').value,
        learning: document.getElementById('grantLearning').value,
        doing_well: document.getElementById('grantDoingWell').value,
        improve: document.getElementById('grantImprove').value,
        address_1: document.getElementById('grantAddress1').value,
        address_2: document.getElementById('grantAddress2').value,
        city: document.getElementById('grantCity').value,
        state: document.getElementById('grantState').value,
        zip: document.getElementById('grantZip').value,
        country: document.getElementById('grantCountry').value,
        screenshot_url: screenshotUrl
    };

    // Check required fields
    const requiredFields = [
        'member_id', 'project_name', 'first_name', 'last_name', 'email', 'birthday',
        'project_description', 'github_url', 'live_url', 'learning', 'doing_well',
        'improve', 'address_1', 'city', 'state', 'zip', 'country'
    ];

    for (let field of requiredFields) {
        if (!formData[field]) {
            submitButton.textContent = originalText;
            submitButton.disabled = false;
            showToast('error', 'Please fill in all required fields', 'Validation Error');
            return;
        }
    }

    submitButton.textContent = '';
    const spinner = createElement('i', 'fas fa-spinner fa-spin');
    submitButton.appendChild(spinner);
    submitButton.appendChild(document.createTextNode(' Submitting...'));

    fetch(`/api/clubs/${clubId}/pizza-grants`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(formData)
    })
    .then(response => response.json())
    .then(data => {
        submitButton.textContent = originalText;
        submitButton.disabled = false;

        if (data.message) {
            document.getElementById('pizzaGrantModal').style.display = 'none';
            document.getElementById('pizzaGrantForm').reset();
            showToast('success', 'Pizza grant submitted successfully!', 'Pizza Grant Submitted');
            // Refresh the submissions list if we're on the pizza tab
            if (document.querySelector('#pizza.active')) {
                loadClubPizzaGrants();
            }
        } else {
            showToast('error', data.error || 'Failed to submit pizza grant', 'Error');
        }
    })
    .catch(error => {
        submitButton.textContent = originalText;
        submitButton.disabled = false;
        showToast('error', 'Error submitting pizza grant', 'Error');
    });
}

// Hackatime Projects functionality
function loadHackatimeProjects() {
    const userId = document.getElementById('hackatimeMemberSelect').value;
    const projectsList = document.getElementById('hackatimeProjectsList');

    if (!userId) {
        projectsList.innerHTML = '';
        const emptyState = createElement('div', 'empty-state');
        const icon = createElement('i', 'fas fa-clock');
        const title = createElement('h3', '', 'Select a member');
        const description = createElement('p', '', 'Choose a member from the dropdown to view their Hackatime coding projects');

        emptyState.appendChild(icon);
        emptyState.appendChild(title);
        emptyState.appendChild(description);
        projectsList.appendChild(emptyState);
        return;
    }

    projectsList.innerHTML = '';
    const loadingState = createElement('div', 'empty-state');
    const loadingIcon = createElement('i', 'fas fa-spinner fa-spin');
    const loadingTitle = createElement('h3', '', 'Loading projects...');
    const loadingDescription = createElement('p', '', 'Fetching Hackatime data');

    loadingState.appendChild(loadingIcon);
    loadingState.appendChild(loadingTitle);
    loadingState.appendChild(loadingDescription);
    projectsList.appendChild(loadingState);

    fetch(`/api/hackatime/projects/${userId}`)
        .then(response => response.json())
        .then(data => {
            projectsList.innerHTML = '';

            if (data.error) {
                const errorState = createElement('div', 'empty-state');
                const errorIcon = createElement('i', 'fas fa-exclamation-triangle');
                errorIcon.style.color = '#f59e0b';
                const errorTitle = createElement('h3', '', 'Unable to load projects');
                const errorDescription = createElement('p', '', data.error);

                errorState.appendChild(errorIcon);
                errorState.appendChild(errorTitle);
                errorState.appendChild(errorDescription);
                projectsList.appendChild(errorState);
                return;
            }

            if (data.projects && data.projects.length > 0) {
                const title = createElement('h4', '', `${data.username}'s Hackatime Projects`);
                title.style.cssText = 'margin-bottom: 1rem; color: #1a202c;';
                projectsList.appendChild(title);

                data.projects.forEach(project => {
                    const card = createElement('div', 'card');
                    card.style.marginBottom = '1rem';

                    const cardHeader = createElement('div', 'card-header');
                    cardHeader.style.cssText = 'display: flex; justify-content: space-between; align-items: flex-start;';

                    const headerDiv = createElement('div');
                    const projectTitle = createElement('h3');
                    projectTitle.style.cssText = 'margin: 0; font-size: 1.125rem; color: #1f2937;';
                    const codeIcon = createElement('i', 'fas fa-code');
                    projectTitle.appendChild(codeIcon);
                    projectTitle.appendChild(document.createTextNode(' ' + project.name));

                    const timeSpan = createElement('span', '', project.formatted_time);
                    timeSpan.style.cssText = 'background: #10b981; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; margin-top: 0.5rem; display: inline-block;';

                    headerDiv.appendChild(projectTitle);
                    headerDiv.appendChild(timeSpan);
                    cardHeader.appendChild(headerDiv);

                    const cardBody = createElement('div', 'card-body');
                    const infoDiv = createElement('div');
                    infoDiv.style.cssText = 'display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.875rem; color: #6b7280; margin-top: 0;';

                    const timeInfo = createElement('span');
                    timeInfo.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                    const clockIcon = createElement('i', 'fas fa-clock');
                    timeInfo.appendChild(clockIcon);
                    timeInfo.appendChild(document.createTextNode(` ${project.total_seconds.toLocaleString()} seconds (${project.formatted_time})`));
                    infoDiv.appendChild(timeInfo);

                    if (project.percent) {
                        const percentInfo = createElement('span');
                        percentInfo.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                        const chartIcon = createElement('i', 'fas fa-chart-pie');
                        percentInfo.appendChild(chartIcon);
                        percentInfo.appendChild(document.createTextNode(` ${project.percent.toFixed(1)}% of total time`));
                        infoDiv.appendChild(percentInfo);
                    }

                    cardBody.appendChild(infoDiv);
                    card.appendChild(cardHeader);
                    card.appendChild(cardBody);
                    projectsList.appendChild(card);
                });
            } else {
                const emptyState = createElement('div', 'empty-state');
                const icon = createElement('i', 'fas fa-clock');
                const title = createElement('h3', '', 'No projects found');
                const description = createElement('p', '', `${data.username} hasn't logged any coding time yet on Hackatime`);

                emptyState.appendChild(icon);
                emptyState.appendChild(title);
                emptyState.appendChild(description);
                projectsList.appendChild(emptyState);
            }
        })
        .catch(error => {
            projectsList.innerHTML = '';
            const errorState = createElement('div', 'empty-state');
            const errorIcon = createElement('i', 'fas fa-exclamation-triangle');
            errorIcon.style.color = '#ef4444';
            const errorTitle = createElement('h3', '', 'Error loading projects');
            const errorDescription = createElement('p', '', 'Failed to fetch Hackatime data. Please try again.');

            errorState.appendChild(errorIcon);
            errorState.appendChild(errorTitle);
            errorState.appendChild(errorDescription);
            projectsList.appendChild(errorState);

            showToast('error', 'Failed to load Hackatime projects', 'Error');
        });
}

function confirmRemoveMember(userId, username) {
    showConfirmModal(
        `Are you sure you want to remove ${username} from the club?`,
        '',
        () => {
            removeMember(userId);
        }
    );
}

function removeMember(userId) {
    if (!clubId) {
        showToast('error', 'Cannot remove member: Club ID is missing.', 'Error');
        console.error('removeMember: clubId is missing.');
        return;
    }
    fetch(`/api/clubs/${clubId}/members/${userId}`, {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('success', 'Member removed successfully', 'Member Removed');
            // Refresh the members list if we're on that section
            if (document.querySelector('#members.active')) {
                document.querySelector(`#membersList [data-user-id="${userId}"]`)?.remove();
            }
        } else {
            showToast('error', data.message || 'Failed to remove member', 'Error');
        }
    })
    .catch(error => {
        showToast('error', 'Error removing member', 'Error');
    });
}

//Event listener for grantMemberSelect to load member data and Hackatime projects
const memberSelect = document.getElementById('grantMemberSelect');
    if (memberSelect) {
        memberSelect.addEventListener('change', function() {
            loadMemberData(this.value);
            loadMemberHackatimeProjects();
        });
    }

// Settings form submission handler
function setupSettingsForm() {
    const settingsForm = document.getElementById('clubSettingsForm');
    if (settingsForm) {
        settingsForm.addEventListener('submit', function(e) {
            e.preventDefault();
            updateClubSettings();
        });
    }
}

function updateClubSettings() {
    if (!clubId) {
        showToast('error', 'Cannot update settings: Club ID is missing.', 'Error');
        console.error('updateClubSettings: clubId is missing.');
        return;
    }

    const clubName = document.getElementById('clubName').value;
    const clubDescription = document.getElementById('clubDescription').value;
    const clubLocation = document.getElementById('clubLocation').value;

    if (!clubName.trim()) {
        showToast('error', 'Club name is required', 'Validation Error');
        return;
    }

    const submitButton = document.querySelector('#clubSettingsForm button[type="submit"]');
    const originalText = submitButton.innerHTML;

    submitButton.disabled = true;
    submitButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';

    fetch(`/api/clubs/${clubId}/settings`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            name: clubName.trim(),
            description: clubDescription.trim(),
            location: clubLocation.trim()
        })
    })
    .then(response => response.json())
    .then(data => {
        submitButton.disabled = false;
        submitButton.innerHTML = originalText;

        if (data.error) {
            showToast('error', data.error, 'Error');
        } else {
            showToast('success', 'Club settings updated successfully!', 'Updated');
            // Update the club header if name changed
            const clubHeader = document.querySelector('.club-info h1');
            if (clubHeader) {
                clubHeader.textContent = clubName.trim();
            }
        }
    })
    .catch(error => {
        submitButton.disabled = false;
        submitButton.innerHTML = originalText;
        showToast('error', 'Error updating club settings', 'Error');
    });
}

function initiateLeadershipTransfer() {
    const newLeaderSelect = document.getElementById('newLeaderSelect');
    const selectedValue = newLeaderSelect.value;
    
    if (!selectedValue) {
        showToast('error', 'Please select a member to transfer leadership to', 'Validation Error');
        return;
    }
    
    const selectedOption = newLeaderSelect.options[newLeaderSelect.selectedIndex];
    const newLeaderName = selectedOption.text.split(' (')[0];
    const newLeaderEmail = selectedOption.text.match(/\((.*?)\)/)[1];
    
    // Update modal content
    document.getElementById('newLeaderName').textContent = newLeaderName;
    document.getElementById('newLeaderEmail').textContent = newLeaderEmail;
    document.getElementById('newLeaderAvatar').textContent = newLeaderName.charAt(0).toUpperCase();
    
    // Reset confirmation input
    document.getElementById('transferConfirmationInput').value = '';
    document.getElementById('confirmTransferButton').disabled = true;
    
    // Show modal
    document.getElementById('transferLeadershipModal').style.display = 'block';
}

function confirmLeadershipTransfer() {
    const newLeaderSelect = document.getElementById('newLeaderSelect');
    const newLeaderId = newLeaderSelect.value;
    
    if (!newLeaderId) {
        showToast('error', 'No leader selected', 'Error');
        return;
    }
    
    const confirmButton = document.getElementById('confirmTransferButton');
    const originalText = confirmButton.innerHTML;
    
    confirmButton.disabled = true;
    confirmButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Transferring...';
    
    fetch(`/api/clubs/${clubId}/transfer-leadership`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            new_leader_id: newLeaderId
        })
    })
    .then(response => response.json())
    .then(data => {
        confirmButton.disabled = false;
        confirmButton.innerHTML = originalText;
        
        if (data.error) {
            showToast('error', data.error, 'Error');
        } else {
            showToast('success', 'Leadership transferred successfully!', 'Success');
            document.getElementById('transferLeadershipModal').style.display = 'none';
            // Redirect to dashboard after a short delay
            setTimeout(() => {
                window.location.href = '/dashboard';
            }, 2000);
        }
    })
    .catch(error => {
        confirmButton.disabled = false;
        confirmButton.innerHTML = originalText;
        showToast('error', 'Error transferring leadership', 'Error');
    });
}

// Add event listener for confirmation input
document.addEventListener('DOMContentLoaded', function() {
    const transferInput = document.getElementById('transferConfirmationInput');
    const confirmButton = document.getElementById('confirmTransferButton');
    
    if (transferInput && confirmButton) {
        transferInput.addEventListener('input', function() {
            const isValid = this.value.trim().toUpperCase() === 'TRANSFER';
            confirmButton.disabled = !isValid;
        });
    }
});

        if (data.message) {
            showToast('success', 'Club settings updated successfully', 'Settings Saved');
            // Update the club header with new information
            const clubTitle = document.querySelector('.club-details h1');
            if (clubTitle) clubTitle.textContent = clubName;

            const locationMeta = document.querySelector('.club-meta span:first-child');
            if (locationMeta) {
                locationMeta.innerHTML = '<i class="fas fa-map-marker-alt"></i> ' + (clubLocation || 'No location set');
            }
        } else {
            showToast('error', data.error || 'Failed to update settings', 'Error');
        }
    })
    .catch(error => {
        submitButton.disabled = false;
        submitButton.innerHTML = originalText;
        showToast('error', 'Error updating settings', 'Error');
        console.error('Settings update error:', error);
    });
}

function loadClubPizzaGrants() {
    if (!clubId) {
        console.warn('loadClubPizzaGrants: clubId is missing. Skipping fetch.');
        const submissionsList = document.getElementById('clubSubmissionsList');
        if (submissionsList) submissionsList.textContent = 'Error: Club information is unavailable to load submissions.';
        return;
    }

    const submissionsList = document.getElementById('clubSubmissionsList');

    fetch(`/api/clubs/${clubId}/pizza-grants`)
        .then(response => response.json())
        .then(data => {
            submissionsList.innerHTML = '';

            if (data.error) {
                const errorState = createElement('div', 'empty-state');
                const errorIcon = createElement('i', 'fas fa-exclamation-triangle');
                errorIcon.style.color = '#f59e0b';
                const errorTitle = createElement('h3', '', 'Error loading submissions');
                const errorDescription = createElement('p', '', data.error);

                errorState.appendChild(errorIcon);
                errorState.appendChild(errorTitle);
                errorState.appendChild(errorDescription);
                submissionsList.appendChild(errorState);
                return;
            }

            if (data.submissions && data.submissions.length > 0) {
                data.submissions.forEach(submission => {
                    const card = createElement('div', 'card');
                    card.style.marginBottom = '1rem';

                    const cardHeader = createElement('div', 'card-header');
                    cardHeader.style.cssText = 'display: flex; justify-content: space-between; align-items: flex-start;';

                    const headerDiv = createElement('div');
                    const title = createElement('h3', '', submission.project_name || 'Untitled Project');
                    title.style.cssText = 'margin: 0; font-size: 1.125rem; color: #1f2937;';

                    const statusSpan = createElement('span', '', submission.status || 'Pending');
                    let statusColor = '#6b7280'; // Default gray
                    if (submission.status === 'Approved') statusColor = '#10b981'; // Green
                    else if (submission.status === 'Rejected') statusColor = '#ef4444'; // Red

                    statusSpan.style.cssText = `background: ${statusColor}; color: white; padding: 0.25rem 0.5rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; margin-top: 0.5rem; display: inline-block;`;

                    headerDiv.appendChild(title);
                    headerDiv.appendChild(statusSpan);
                    cardHeader.appendChild(headerDiv);

                    const grantAmountDiv = createElement('div');
                    grantAmountDiv.style.cssText = 'text-align: right;';
                    const grantAmount = createElement('div', '', submission.grant_amount || '$0');
                    grantAmount.style.cssText = 'font-size: 1.5rem; font-weight: bold; color: #ec3750;';
                    const grantLabel = createElement('div', '', 'Grant Amount');
                    grantLabel.style.cssText = 'font-size: 0.75rem; color: #6b7280; text-transform: uppercase;';
                    grantAmountDiv.appendChild(grantAmount);
                    grantAmountDiv.appendChild(grantLabel);
                    cardHeader.appendChild(grantAmountDiv);

                    const cardBody = createElement('div', 'card-body');

                    if (submission.description) {
                        const description = createElement('p', '', submission.description);
                        description.style.cssText = 'margin-bottom: 1rem; color: #6b7280;';
                        cardBody.appendChild(description);
                    }

                    const infoDiv = createElement('div');
                    infoDiv.style.cssText = 'display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.875rem; color: #6b7280;';

                    const submitterSpan = createElement('span');
                    submitterSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                    const submitterIcon = createElement('i', 'fas fa-user');
                    submitterSpan.appendChild(submitterIcon);
                    submitterSpan.appendChild(document.createTextNode(' ' + (submission.first_name && submission.last_name ? 
                        `${submission.first_name} ${submission.last_name}` : submission.github_username || 'Unknown')));
                    infoDiv.appendChild(submitterSpan);

                    if (submission.hours) {
                        const hoursSpan = createElement('span');
                        hoursSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                        const hoursIcon = createElement('i', 'fas fa-clock');
                        hoursSpan.appendChild(hoursIcon);
                        hoursSpan.appendChild(document.createTextNode(' ' + submission.hours + ' hours'));
                        infoDiv.appendChild(hoursSpan);
                    }

                    if (submission.created_time) {
                        const dateSpan = createElement('span');
                        dateSpan.style.cssText = 'display: flex; align-items: center; gap: 0.25rem;';
                        const dateIcon = createElement('i', 'fas fa-calendar');
                        dateSpan.appendChild(dateIcon);
                        dateSpan.appendChild(document.createTextNode(' ' + new Date(submission.created_time).toLocaleDateString()));
                        infoDiv.appendChild(dateSpan);
                    }

                    cardBody.appendChild(infoDiv);

                    if (submission.code_url || submission.playable_url) {
                        const linksDiv = createElement('div');
                        linksDiv.style.cssText = 'margin-top: 1rem; display: flex; gap: 0.5rem; flex-wrap: wrap;';

                        if (submission.code_url) {
                            const codeLink = createElement('a');
                            codeLink.href = submission.code_url;
                            codeLink.target = '_blank';
                            codeLink.className = 'btn btn-secondary btn-sm';
                            codeLink.innerHTML = '<i class="fab fa-github"></i> Code';
                            linksDiv.appendChild(codeLink);
                        }

                        if (submission.playable_url) {
                            const liveLink = createElement('a');
                            liveLink.href = submission.playable_url;
                            liveLink.target = '_blank';
                            liveLink.className = 'btn btn-secondary btn-sm';
                            liveLink.innerHTML = '<i class="fas fa-external-link-alt"></i> Live Demo';
                            linksDiv.appendChild(liveLink);
                        }

                        cardBody.appendChild(linksDiv);
                    }

                    card.appendChild(cardHeader);
                    card.appendChild(cardBody);
                    submissionsList.appendChild(card);
                });
            } else {
                const emptyState = createElement('div', 'empty-state');
                const icon = createElement('i', 'fas fa-pizza-slice');
                const title = createElement('h3', '', 'No submissions yet');
                const description = createElement('p', '', 'Submit your coding projects to earn pizza for the club!');

                emptyState.appendChild(icon);
                emptyState.appendChild(title);
                emptyState.appendChild(description);
                submissionsList.appendChild(emptyState);
            }
        })
        .catch(error => {
            console.error('Error loading club pizza grants:', error);
            submissionsList.innerHTML = '';
            const errorState = createElement('div', 'empty-state');
            const errorIcon = createElement('i', 'fas fa-exclamation-triangle');
            errorIcon.style.color = '#ef4444';
            const errorTitle = createElement('h3', '', 'Error loading submissions');
            const errorDescription = createElement('p', '', 'Failed to fetch pizza grant submissions. Please try again.');

            errorState.appendChild(errorIcon);
            errorState.appendChild(errorTitle);
            errorState.appendChild(errorDescription);
            submissionsList.appendChild(errorState);

            showToast('error', 'Failed to load pizza grant submissions', 'Error');
        });
}

function loadShop() {
    const shopList = document.getElementById('shopList');
    shopList.innerHTML = '';

    // Fetch club balance
    fetch(`/api/clubs/${clubId}/balance`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showToast('error', data.error || 'Failed to load club balance', 'Error');
            } else {
                const balanceDiv = createElement('div');
                balanceDiv.style.cssText = 'font-size: 1.2rem; font-weight: bold; margin-bottom: 1rem;';
                balanceDiv.textContent = `Club Balance: $${data.balance}`;
                shopList.appendChild(balanceDiv);
            }
        })
        .catch(error => {
            showToast('error', 'Error loading club balance', 'Error');
        });

    // Define shop items
    const shopItems = [
        {
            name: 'Pizza for your club!',
            description: 'Get a virtual card to buy pizza for your club!',
            action: 'purchasePizza'
        }
    ];

    shopItems.forEach(item => {
        const shopItemDiv = createElement('div', 'shop-item');
        shopItemDiv.style.cssText = 'border: 1px solid #e2e8f0; padding: 1rem; margin-bottom: 1rem; border-radius: 0.375rem; cursor: pointer; transition: all 0.2s ease-in-out;';

        const itemName = createElement('h3', '', item.name);
        itemName.style.cssText = 'font-size: 1rem; margin-bottom: 0.5rem;';
        shopItemDiv.appendChild(itemName);

        const itemDescription = createElement('p', '', item.description);
        itemDescription.style.cssText = 'color: #6b7280; font-size: 0.875rem;';
        shopItemDiv.appendChild(itemDescription);

        shopItemDiv.onclick = () => {
            window[item.action]();
        };

        shopList.appendChild(shopItemDiv);
    });
}

function purchasePizza() {
    // Redirect to pizza order form
    window.location.href = `/pizza-order/${clubId}`;
}

// Add hover effect styles for shop items
document.addEventListener('DOMContentLoaded', function() {
    const shopItems = document.querySelectorAll('.shop-item');
    shopItems.forEach(item => {
        item.addEventListener('mouseenter', function() {
            this.style.borderColor = '#ec3750';
            this.style.transform = 'translateY(-4px)';
            this.style.boxShadow = '0 8px 25px rgba(236, 55, 80, 0.15)';
        });

        item.addEventListener('mouseleave', function() {
            this.style.borderColor = '#e2e8f0';
            this.style.transform = 'translateY(0)';
            this.style.boxShadow = 'none';
        });
    });
});

// Event handlers are set up in the DOMContentLoaded event at the top of this file

// Functionality to remove grant amount and integrate airtable will be addressed.