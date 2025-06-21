// Mobile Club Dashboard JavaScript
class MobileClubDashboard {
    constructor() {
        this.clubId = null;
        this.joinCode = null;
        this.isLeader = false;
        this.currentSection = 'dashboard';
        this.isLoading = true;
        this.loadingTimeout = null;
        this.data = {
            posts: [],
            assignments: [],
            meetings: [],
            projects: [],
            resources: [],
            submissions: []
        };

        this.init();
    }

    init() {
        console.log('Initializing mobile club dashboard...');

        // Show loading screen
        this.showLoadingScreen();

        // Get club data
        this.extractClubData();

        // Set up event listeners
        this.setupEventListeners();

        // Initialize PWA functionality
        this.initPWA();

        // Add enhanced interactions
        this.addRippleEffect();
        this.createActiveIndicator();

        // Load initial data
        this.loadInitialData();

        // Hide loading screen immediately after data loads
        this.hideLoadingScreen();
    }

    extractClubData() {
        const dashboard = document.getElementById('mobileDashboard');
        if (dashboard) {
            this.clubId = dashboard.dataset.clubId;
            this.joinCode = dashboard.dataset.joinCode;
            this.isLeader = window.clubData?.isLeader || false;

            console.log('Retrieved Club ID:', this.clubId);
            console.log('Retrieved Join Code:', this.joinCode);
            console.log('Is Leader:', this.isLeader);
        }
    }

    showLoadingScreen() {
        const loadingScreen = document.getElementById('mobileLoadingScreen');
        const dashboard = document.getElementById('mobileDashboard');

        if (loadingScreen && dashboard) {
            loadingScreen.style.display = 'flex';
            dashboard.style.display = 'none';
            document.body.classList.add('mobile-dashboard-active');
        }
    }

    hideLoadingScreen() {
        const loadingScreen = document.getElementById('mobileLoadingScreen');
        const dashboard = document.getElementById('mobileDashboard');

        if (loadingScreen && dashboard) {
            loadingScreen.style.opacity = '0';
            setTimeout(() => {
                loadingScreen.style.display = 'none';
                dashboard.style.display = 'flex';
                this.isLoading = false;

                // Trigger entrance animations
                this.triggerEntranceAnimations();
            }, 300);
        }
    }

    triggerEntranceAnimations() {
        // Immediate animations - no delays
        const statCards = document.querySelectorAll('.stat-card');
        statCards.forEach((card) => {
            card.style.animationDelay = '0s';
        });

        // Immediate animations - no delays
        const quickActions = document.querySelectorAll('.quick-action-btn');
        quickActions.forEach((button) => {
            button.style.animationDelay = '0s';
        });

        // Add scroll animations
        this.setupScrollAnimations();
    }

    addRippleEffect() {
        // Enhanced ripple effect for all interactive elements
        const selectors = [
            '.mobile-btn-primary',
            '.quick-action-btn',
            '.stat-card',
            '.mobile-card',
            '.nav-tab',
            '.action-btn',
            '.member-card'
        ];
        
        selectors.forEach(selector => {
            document.addEventListener('click', (e) => {
                const element = e.target.closest(selector);
                if (!element) return;
                
                this.createRipple(element, e);
            });
        });
    }

    createRipple(element, event) {
        const ripple = document.createElement('span');
        const rect = element.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height) * 1.5;
        const x = event.clientX - rect.left - size / 2;
        const y = event.clientY - rect.top - size / 2;
        
        ripple.className = 'ripple-effect';
        ripple.style.cssText = `
            position: absolute;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.3);
            transform: scale(0);
            animation: superRipple 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94);
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            pointer-events: none;
            z-index: 1000;
        `;
        
        element.style.position = 'relative';
        element.style.overflow = 'hidden';
        element.appendChild(ripple);
        
        setTimeout(() => {
            if (ripple.parentNode) {
                ripple.remove();
            }
        }, 400);
    }

    setupScrollAnimations() {
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                } else {
                    entry.target.style.opacity = '0';
                    entry.target.style.transform = 'translateY(20px)';
                }
            });
        }, observerOptions);

        // Observe cards for scroll animations
        const animatedElements = document.querySelectorAll('.mobile-card');
        animatedElements.forEach(el => {
            el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
            observer.observe(el);
        });
    }

    setupEventListeners() {
        // Navigation tabs
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                e.preventDefault();
                const section = tab.dataset.section;
                this.openTab(section);
            });
        });

        // Touch gestures for better mobile experience
        this.setupTouchGestures();

        // Form submissions
        this.setupFormHandlers();

        // Pull to refresh
        this.setupPullToRefresh();
    }

    setupTouchGestures() {
        let startY = 0;
        let startX = 0;
        const content = document.getElementById('mobileContent');

        if (content) {
            content.addEventListener('touchstart', (e) => {
                startY = e.touches[0].clientY;
                startX = e.touches[0].clientX;
            }, { passive: true });

            content.addEventListener('touchmove', (e) => {
                // Prevent rubber band effect on iOS
                if (content.scrollTop === 0 && e.touches[0].clientY > startY) {
                    e.preventDefault();
                }
            }, { passive: false });
        }
    }

    setupFormHandlers() {
        // Mobile club settings form
        const settingsForm = document.getElementById('mobileClubSettingsForm');
        if (settingsForm) {
            settingsForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.saveClubSettings();
            });
        }
    }

    setupPullToRefresh() {
        let startY = 0;
        let pullDistance = 0;
        const content = document.getElementById('mobileContent');
        const threshold = 80;

        if (content) {
            content.addEventListener('touchstart', (e) => {
                if (content.scrollTop === 0) {
                    startY = e.touches[0].clientY;
                }
            }, { passive: true });

            content.addEventListener('touchmove', (e) => {
                if (content.scrollTop === 0 && startY > 0) {
                    pullDistance = e.touches[0].clientY - startY;
                    if (pullDistance > 0 && pullDistance < threshold * 2) {
                        content.style.transform = `translateY(${pullDistance * 0.5}px)`;
                        content.style.opacity = `${1 - (pullDistance / threshold) * 0.3}`;
                    }
                }
            }, { passive: true });

            content.addEventListener('touchend', () => {
                if (pullDistance > threshold) {
                    this.refreshData();
                }
                content.style.transform = '';
                content.style.opacity = '';
                startY = 0;
                pullDistance = 0;
            }, { passive: true });
        }
    }

    async refreshData() {
        await this.loadAllData();
    }

    openTab(sectionName) {
        if (this.isLoading) return;

        console.log('Opening tab:', sectionName);

        // Handle detail sections
        if (['schedule', 'resources', 'pizza', 'shop', 'ysws', 'settings'].includes(sectionName)) {
            this.openDetailSection(sectionName);
            return;
        }

        // Update active tab with sliding indicator
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.remove('active');
        });

        const activeTab = document.querySelector(`.nav-tab[data-section="${sectionName}"]`);
        if (activeTab) {
            activeTab.classList.add('active');
            this.updateActiveIndicator(activeTab);
        }

        // Fast section switching without complex animations
        document.querySelectorAll('.mobile-section').forEach(section => {
            section.classList.remove('active');
        });

        const targetSection = document.getElementById(`${sectionName}Section`);
        if (targetSection) {
            targetSection.classList.add('active');
            this.currentSection = sectionName;

            // Load section data if needed
            this.loadSectionData(sectionName);
        }
    }

    updateActiveIndicator(activeTab) {
        const indicator = document.querySelector('.nav-active-indicator') || this.createActiveIndicator();
        const tabRect = activeTab.getBoundingClientRect();
        const navRect = document.querySelector('.nav-tabs').getBoundingClientRect();
        
        const left = tabRect.left - navRect.left;
        const width = tabRect.width;
        
        indicator.style.transform = `translateX(${left}px)`;
        indicator.style.width = `${width}px`;
    }

    createActiveIndicator() {
        const indicator = document.createElement('div');
        indicator.className = 'nav-active-indicator';
        document.querySelector('.nav-tabs').appendChild(indicator);
        return indicator;
    }

    openDetailSection(sectionName) {
        const detailSection = document.getElementById(`${sectionName}Detail`);
        if (detailSection) {
            // Add body class to hide header/nav
            document.body.classList.add('detail-section-open');
            
            detailSection.style.display = 'flex';
            detailSection.style.transform = 'translateX(100%)';
            detailSection.style.transition = 'transform 0.2s ease';
            detailSection.classList.add('active');

            setTimeout(() => {
                detailSection.style.transform = 'translateX(0)';
            }, 10);

            // Load section data
            this.loadSectionData(sectionName);
        }
    }

    closeDetailSection() {
        const activeDetail = document.querySelector('.detail-section.active, .detail-section[style*="flex"]');
        if (activeDetail) {
            activeDetail.style.transform = 'translateX(100%)';
            activeDetail.classList.remove('active');
            
            setTimeout(() => {
                activeDetail.style.display = 'none';
                // Remove body class to show header/nav again
                document.body.classList.remove('detail-section-open');
            }, 200);
        }
    }

    async loadInitialData() {
        await this.loadAllData();
        this.updateStats();
    }

    async loadAllData() {
        try {
            const promises = [
                this.fetchData('posts'),
                this.fetchData('assignments'),
                this.fetchData('meetings'),
                this.fetchData('projects')
            ];

            await Promise.all(promises);
        } catch (error) {
            console.error('Error loading data:', error);
            this.showToast('Error loading data', 'error');
        }
    }

    async loadSectionData(sectionName) {
        switch (sectionName) {
            case 'stream':
                await this.loadPosts();
                break;
            case 'assignments':
                await this.loadAssignments();
                break;
            case 'projects':
                await this.loadProjects();
                break;
            case 'schedule':
                await this.loadMeetings();
                break;
            case 'resources':
                await this.loadResources();
                break;
            case 'pizza':
                await this.loadSubmissions();
                break;
        }
    }

    async fetchData(endpoint) {
        try {
            const response = await fetch(`/api/clubs/${this.clubId}/${endpoint}`);
            if (response.ok) {
                const data = await response.json();
                console.log(`Fetched ${endpoint} data:`, data);
                
                // Handle different response formats
                let arrayData;
                if (Array.isArray(data)) {
                    arrayData = data;
                } else if (data && typeof data === 'object') {
                    // Try common array property names
                    arrayData = data.items || data.data || data[endpoint] || data.results || [];
                    
                    // If it's still not an array, wrap single object in array
                    if (!Array.isArray(arrayData)) {
                        arrayData = [data];
                    }
                } else {
                    arrayData = [];
                }
                
                this.data[endpoint] = arrayData;
                console.log(`Processed ${endpoint} data:`, arrayData);
                return arrayData;
            } else {
                console.error(`Failed to fetch ${endpoint}: ${response.status} ${response.statusText}`);
                throw new Error(`Failed to fetch ${endpoint}: ${response.status}`);
            }
        } catch (error) {
            console.error(`Error fetching ${endpoint}:`, error);
            throw error;
        }
    }

    async loadPosts() {
        const container = document.getElementById('mobilePostsList');
        if (!container) return;

        this.showSectionLoading(container, 'Loading posts...');

        try {
            const posts = await this.fetchData('posts');
            console.log('Loaded posts:', posts);

            if (!Array.isArray(posts) || posts.length === 0) {
                container.innerHTML = this.getEmptyState('stream', 'No posts yet', 'Be the first to share something!');
            } else {
                container.innerHTML = posts.map(post => this.renderPost(post)).join('');
            }
        } catch (error) {
            console.error('Error loading posts:', error);
            container.innerHTML = this.getEmptyState('exclamation-triangle', 'Error loading posts', 'Please try again later');
        }
    }

    async loadAssignments() {
        const container = document.getElementById('mobileAssignmentsList');
        if (!container) return;

        this.showSectionLoading(container, 'Loading assignments...');

        try {
            const assignments = await this.fetchData('assignments');
            console.log('Loaded assignments:', assignments);

            if (!Array.isArray(assignments) || assignments.length === 0) {
                container.innerHTML = this.getEmptyState('tasks', 'No assignments yet', 'Check back for new coding challenges!');
            } else {
                container.innerHTML = assignments.map(assignment => this.renderAssignment(assignment)).join('');
            }
        } catch (error) {
            console.error('Error loading assignments:', error);
            container.innerHTML = this.getEmptyState('exclamation-triangle', 'Error loading assignments', 'Please try again later');
        }
    }

    async loadMeetings() {
        const container = document.getElementById('mobileMeetingsList');
        if (!container) return;

        this.showSectionLoading(container, 'Loading meetings...');

        try {
            const meetings = await this.fetchData('meetings');
            console.log('Loaded meetings:', meetings);

            if (!Array.isArray(meetings) || meetings.length === 0) {
                container.innerHTML = this.getEmptyState('calendar-times', 'No meetings scheduled', 'Check back for upcoming events!');
            } else {
                container.innerHTML = meetings.map(meeting => this.renderMeeting(meeting)).join('');
            }
        } catch (error) {
            console.error('Error loading meetings:', error);
            container.innerHTML = this.getEmptyState('exclamation-triangle', 'Error loading meetings', 'Please try again later');
        }
    }

    async loadProjects() {
        // Projects are handled differently - they show Hackatime integration
        const projects = await this.fetchData('projects');
        this.updateProjectsCount(projects);
    }

    async loadHackatimeProjects() {
        const memberId = document.getElementById('mobileHackatimeMemberSelect').value;
        const container = document.getElementById('mobileHackatimeProjectsList');
        
        if (!memberId || !container) {
            container.innerHTML = this.getEmptyState('user', 'Select a member', 'Choose a member to view their coding projects');
            return;
        }

        this.showSectionLoading(container, 'Loading Hackatime projects...');

        try {
            const response = await fetch(`/api/hackatime/projects/${memberId}`);
            const data = await response.json();
            
            if (data.error) {
                container.innerHTML = this.getEmptyState('exclamation-triangle', 'Unable to load projects', data.error);
                return;
            }
            
            if (data.projects && data.projects.length > 0) {
                const title = `<h4 style="margin-bottom: 1rem; color: #1a202c;">${data.username}'s Hackatime Projects</h4>`;
                const projectsHtml = data.projects.map(project => this.renderHackatimeProject(project)).join('');
                container.innerHTML = title + projectsHtml;
            } else {
                container.innerHTML = this.getEmptyState('clock', 'No projects found', `${data.username} hasn't logged any coding time yet on Hackatime`);
            }
        } catch (error) {
            console.error('Error loading Hackatime projects:', error);
            container.innerHTML = this.getEmptyState('exclamation-triangle', 'Error loading projects', 'Failed to fetch Hackatime data. Please try again.');
        }
    }

    renderHackatimeProject(project) {
        return `
            <div class="mobile-card" style="margin-bottom: 1rem;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem;">
                    <h4 style="margin: 0; color: #1a202c; font-size: 1rem;">
                        <i class="fas fa-code"></i> ${project.name}
                    </h4>
                    <span style="background: #10b981; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600;">${project.formatted_time}</span>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.875rem; color: #6b7280;">
                    <span style="display: flex; align-items: center; gap: 0.25rem;">
                        <i class="fas fa-clock"></i> ${project.total_seconds.toLocaleString()} seconds
                    </span>
                    ${project.percent ? `<span style="display: flex; align-items: center; gap: 0.25rem;"><i class="fas fa-chart-pie"></i> ${project.percent.toFixed(1)}% of total time</span>` : ''}
                </div>
            </div>
        `;
    }

    async loadResources() {
        const container = document.getElementById('mobileResourcesList');
        if (!container) return;

        this.showSectionLoading(container, 'Loading resources...');

        try {
            const resources = await this.fetchData('resources');
            console.log('Loaded resources:', resources);

            if (!Array.isArray(resources) || resources.length === 0) {
                container.innerHTML = this.getEmptyState('book', 'No resources yet', 'Add helpful links and materials!');
            } else {
                container.innerHTML = resources.map(resource => this.renderResource(resource)).join('');
            }
        } catch (error) {
            console.error('Error loading resources:', error);
            container.innerHTML = this.getEmptyState('exclamation-triangle', 'Error loading resources', 'Please try again later');
        }
    }

    async loadSubmissions() {
        const container = document.getElementById('mobileClubSubmissionsList');
        if (!container) return;

        this.showSectionLoading(container, 'Loading submissions...');

        // This would connect to the pizza grant API
        setTimeout(() => {
            container.innerHTML = this.getEmptyState('hand-holding-usd', 'No submissions yet', 'Submit your first project for a grant!');
        }, 1000);
    }

    showSectionLoading(container, text) {
        container.innerHTML = `
            <div class="section-loading">
                <i class="fas fa-spinner fa-spin"></i>
                <div class="section-loading-text">${text}</div>
            </div>
        `;
    }

    getEmptyState(icon, title, description) {
        return `
            <div class="empty-state-mobile">
                <i class="fas fa-${icon}"></i>
                <h3>${title}</h3>
                <p>${description}</p>
            </div>
        `;
    }

    renderPost(post) {
        const authorName = post.author_name || post.author || 'Unknown';
        const content = post.content || 'No content';
        const createdAt = post.created_at || post.timestamp || new Date().toISOString();
        
        return `
            <div class="mobile-card" style="margin-bottom: 1rem;">
                <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem;">
                    <div class="member-avatar" style="width: 35px; height: 35px; font-size: 0.8rem;">
                        ${authorName.charAt(0).toUpperCase()}
                    </div>
                    <div>
                        <div style="font-weight: 600; color: #1a202c; font-size: 0.9rem;">${authorName}</div>
                        <div style="font-size: 0.75rem; color: #6b7280;">${this.timeAgo(createdAt)}</div>
                    </div>
                </div>
                <p style="margin: 0; color: #4a5568; line-height: 1.4;">${content}</p>
            </div>
        `;
    }

    renderAssignment(assignment) {
        const title = assignment.title || assignment.name || 'Untitled Assignment';
        const description = assignment.description || 'No description available';
        const dueDate = assignment.due_date ? new Date(assignment.due_date) : null;
        const isOverdue = dueDate && dueDate < new Date();

        return `
            <div class="mobile-card" style="margin-bottom: 1rem; ${isOverdue ? 'border-left: 4px solid #ef4444;' : ''}">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem;">
                    <h4 style="margin: 0; color: #1a202c; font-size: 1rem;">${title}</h4>
                    ${dueDate ? `<span style="font-size: 0.75rem; color: ${isOverdue ? '#ef4444' : '#6b7280'}; white-space: nowrap;">${this.formatDate(dueDate)}</span>` : ''}
                </div>
                <p style="margin: 0; color: #6b7280; font-size: 0.875rem; line-height: 1.4;">${description}</p>
                ${isOverdue ? '<div style="margin-top: 0.5rem; color: #ef4444; font-size: 0.75rem; font-weight: 600;"><i class="fas fa-exclamation-triangle"></i> Overdue</div>' : ''}
            </div>
        `;
    }

    renderMeeting(meeting) {
        const title = meeting.title || meeting.name || 'Untitled Meeting';
        const description = meeting.description || '';
        const location = meeting.location || '';
        const link = meeting.link || meeting.url || '';
        const datetime = meeting.datetime || meeting.date || meeting.time || new Date().toISOString();
        const meetingDate = new Date(datetime);
        const isUpcoming = meetingDate > new Date();

        return `
            <div class="mobile-card" style="margin-bottom: 1rem;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem;">
                    <h4 style="margin: 0; color: #1a202c; font-size: 1rem;">${title}</h4>
                    <span style="font-size: 0.75rem; color: ${isUpcoming ? '#10b981' : '#6b7280'}; white-space: nowrap;">
                        ${this.formatDateTime(meetingDate)}
                    </span>
                </div>
                ${description ? `<p style="margin: 0 0 0.5rem 0; color: #6b7280; font-size: 0.875rem;">${description}</p>` : ''}
                ${location ? `<div style="font-size: 0.75rem; color: #6b7280;"><i class="fas fa-map-marker-alt"></i> ${location}</div>` : ''}
                ${link ? `<div style="margin-top: 0.5rem;"><a href="${link}" target="_blank" style="color: #ec3750; font-size: 0.75rem; text-decoration: none;"><i class="fas fa-external-link-alt"></i> Join Meeting</a></div>` : ''}
            </div>
        `;
    }

    renderResource(resource) {
        const title = resource.title || resource.name || 'Untitled Resource';
        const description = resource.description || '';
        const url = resource.url || resource.link || '#';
        const icon = resource.icon || 'link';
        
        return `
            <div class="mobile-card" style="margin-bottom: 1rem;">
                <div style="display: flex; align-items: center; gap: 0.75rem;">
                    <div style="width: 35px; height: 35px; background: rgba(236, 55, 80, 0.1); color: #ec3750; border-radius: 8px; display: flex; align-items: center; justify-content: center;">
                        <i class="fas fa-${icon}"></i>
                    </div>
                    <div style="flex: 1;">
                        <h4 style="margin: 0 0 0.25rem 0; color: #1a202c; font-size: 0.9rem;">${title}</h4>
                        ${description ? `<p style="margin: 0 0 0.5rem 0; color: #6b7280; font-size: 0.8rem;">${description}</p>` : ''}
                        <a href="${url}" target="_blank" style="color: #ec3750; font-size: 0.75rem; text-decoration: none;">
                            <i class="fas fa-external-link-alt"></i> Visit Link
                        </a>
                    </div>
                </div>
            </div>
        `;
    }

    updateStats() {
        // Update dashboard stats
        const counters = {
            'mobileMeetingsCount': this.data.meetings?.length || 0,
            'mobileAssignmentsCount': this.data.assignments?.length || 0,
            'mobileProjectsCount': this.data.projects?.length || 0
        };

        Object.entries(counters).forEach(([id, count]) => {
            const element = document.getElementById(id);
            if (element) {
                this.animateCounter(element, count);
            }
        });
    }

    updateProjectsCount(projects = null) {
        const projectsData = projects || this.data.projects || [];
        const element = document.getElementById('mobileProjectsCount');
        if (element) {
            this.animateCounter(element, projectsData.length);
        }
    }

    animateSectionContent(section) {
        // Simplified content appearance for better performance
        const cards = section.querySelectorAll('.mobile-card, .member-card, .ysws-item, .shop-item-mobile');
        cards.forEach((card) => {
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        });

        const lists = section.querySelectorAll('.mobile-members-list, .shop-items-mobile, .ysws-items');
        lists.forEach(list => {
            list.style.opacity = '1';
            list.style.transform = 'translateY(0)';
        });
    }

    animateCounter(element, targetCount) {
        let current = 0;
        const increment = targetCount / 20;
        const timer = setInterval(() => {
            current += increment;
            if (current >= targetCount) {
                current = targetCount;
                clearInterval(timer);
            }
            element.textContent = Math.floor(current);
        }, 50);
    }

    async saveClubSettings() {
        const name = document.getElementById('mobileClubName').value;
        const description = document.getElementById('mobileClubDescription').value;
        const location = document.getElementById('mobileClubLocation').value;

        const button = document.querySelector('#mobileClubSettingsForm .save-btn');
        button.classList.add('btn-loading');
        button.disabled = true;

        try {
            const response = await fetch(`/api/clubs/${this.clubId}/settings`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ name, description, location })
            });

            if (response.ok) {
                this.showToast('Settings saved successfully!', 'success');
                // Update header with new name
                const headerTitle = document.querySelector('.club-info-mobile h1');
                if (headerTitle) headerTitle.textContent = name;
            } else {
                throw new Error('Failed to save settings');
            }
        } catch (error) {
            console.error('Error saving settings:', error);
            this.showToast('Failed to save settings', 'error');
        } finally {
            button.classList.remove('btn-loading');
            button.disabled = false;
        }
    }

    // PWA Functionality
    initPWA() {
        let deferredPrompt;

        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            deferredPrompt = e;
            this.showPWAInstall();
        });

        const installBtn = document.getElementById('pwaInstallBtn');
        if (installBtn) {
            installBtn.addEventListener('click', async () => {
                if (deferredPrompt) {
                    deferredPrompt.prompt();
                    const { outcome } = await deferredPrompt.userChoice;
                    if (outcome === 'accepted') {
                        this.hidePWAInstall();
                    }
                    deferredPrompt = null;
                }
            });
        }
    }

    showPWAInstall() {
        const card = document.getElementById('pwaInstallCard');
        if (card) {
            card.style.display = 'flex';
        }
    }

    hidePWAInstall() {
        const card = document.getElementById('pwaInstallCard');
        if (card) {
            card.style.display = 'none';
        }
    }

    // Utility Functions
    timeAgo(dateString) {
        const date = new Date(dateString);
        const now = new Date();
        const seconds = Math.floor((now - date) / 1000);

        const intervals = {
            year: 31536000,
            month: 2592000,
            week: 604800,
            day: 86400,
            hour: 3600,
            minute: 60
        };

        for (const [unit, secondsInUnit] of Object.entries(intervals)) {
            const interval = Math.floor(seconds / secondsInUnit);
            if (interval >= 1) {
                return `${interval} ${unit}${interval !== 1 ? 's' : ''} ago`;
            }
        }

        return 'Just now';
    }

    formatDate(date) {
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric'
        });
    }

    formatDateTime(date) {
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: 'numeric',
            minute: '2-digit'
        });
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `
            <div style="display: flex; align-items: center; gap: 0.5rem;">
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}" style="animation: bounceIn 0.6s cubic-bezier(0.68, -0.55, 0.265, 1.55);"></i>
                <span>${message}</span>
            </div>
        `;

        const colors = {
            success: '#10b981',
            error: '#ef4444',
            info: '#3b82f6'
        };

        toast.style.cssText = `
            background: ${colors[type]};
            color: white;
            padding: 1rem;
            border-radius: 12px;
            margin-bottom: 0.5rem;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
            transform: translateX(100%) scale(0.9);
            transition: all 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
            opacity: 0;
            position: relative;
            overflow: hidden;
        `;

        // Add shimmer effect
        const shimmer = document.createElement('div');
        shimmer.style.cssText = `
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
            animation: shimmer 2s ease-in-out;
        `;
        toast.appendChild(shimmer);

        container.appendChild(toast);

        // Animate in
        setTimeout(() => {
            toast.style.transform = 'translateX(0) scale(1)';
            toast.style.opacity = '1';
        }, 50);

        // Add exit animation
        setTimeout(() => {
            toast.style.transform = 'translateX(100%) scale(0.9) rotateZ(5deg)';
            toast.style.opacity = '0';
            setTimeout(() => {
                if (container.contains(toast)) {
                    container.removeChild(toast);
                }
            }, 400);
        }, 3000);

        // Add shimmer keyframe
        if (!document.getElementById('shimmer-styles')) {
            const style = document.createElement('style');
            style.id = 'shimmer-styles';
            style.textContent = `
                @keyframes shimmer {
                    0% { left: -100%; }
                    100% { left: 100%; }
                }
            `;
            document.head.appendChild(style);
        }
    }
}

// Global functions for compatibility with existing code
let mobileDashboard;

function openTab(sectionName) {
    if (mobileDashboard) {
        mobileDashboard.openTab(sectionName);
    }
}

function hidePWAInstall() {
    if (mobileDashboard) {
        mobileDashboard.hidePWAInstall();
    }
}

function closeDetailSection() {
    if (mobileDashboard) {
        mobileDashboard.closeDetailSection();
    }
}

// Placeholder functions for features that need desktop integration
function purchasePizza() {
    console.log('Pizza purchase functionality would be integrated here');
    if (mobileDashboard) {
        mobileDashboard.showToast('Feature coming soon!', 'info');
    }
}

function showQRModal() {
    const modal = document.getElementById('qrModal');
    if (modal && mobileDashboard) {
        const joinCode = mobileDashboard.joinCode;
        const clubId = mobileDashboard.clubId;
        const joinUrl = `${window.location.origin}/join-club?code=${joinCode}`;
        
        // Generate QR code
        const qrContainer = document.getElementById('qrCode');
        if (qrContainer && window.QRCode) {
            qrContainer.innerHTML = ''; // Clear previous QR code
            
            // Create canvas element explicitly
            const canvas = document.createElement('canvas');
            qrContainer.appendChild(canvas);
            
            QRCode.toCanvas(canvas, joinUrl, {
                width: 200,
                height: 200,
                margin: 2,
                color: {
                    dark: '#1a202c',
                    light: '#ffffff'
                }
            }, function (error) {
                if (error) {
                    console.error('QR Code generation failed:', error);
                    qrContainer.innerHTML = '<p style="color: #ef4444;">Failed to generate QR code</p>';
                } else {
                    console.log('QR Code generated successfully');
                }
            });
        }
        
        // Update join URL in modal
        const joinUrlElement = document.getElementById('joinUrl');
        if (joinUrlElement) {
            joinUrlElement.value = joinUrl;
        }
        
        // Update join code in modal
        const joinCodeElement = document.getElementById('modalJoinCode');
        if (joinCodeElement) {
            joinCodeElement.value = joinCode;
        }
        
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
}

async function generateNewJoinCode() {
    if (!mobileDashboard) return;
    
    const button = document.querySelector('.action-btn[onclick="generateNewJoinCode()"]');
    const originalIcon = button.innerHTML;
    
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
    button.disabled = true;
    
    try {
        const response = await fetch(`/api/clubs/${mobileDashboard.clubId}/join-code`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            console.log('New join code generated:', data.join_code);
            
            // Update the join code in the mobile dashboard
            mobileDashboard.joinCode = data.join_code;
            
            // Update the header join code display
            const joinCodeDisplay = document.querySelector('.join-code-mobile strong');
            if (joinCodeDisplay) {
                joinCodeDisplay.textContent = `Join Code: ${data.join_code}`;
            }
            
            if (mobileDashboard) {
                mobileDashboard.showToast('New join code generated!', 'success');
            }
        } else {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Failed to generate new join code');
        }
    } catch (error) {
        console.error('Error generating new join code:', error);
        if (mobileDashboard) {
            mobileDashboard.showToast(error.message || 'Failed to generate new join code', 'error');
        }
    } finally {
        button.innerHTML = originalIcon;
        button.disabled = false;
    }
}

async function createPost() {
    const content = document.getElementById('mobilePostContent').value.trim();
    if (!content) {
        if (mobileDashboard) {
            mobileDashboard.showToast('Please enter some content for your post', 'error');
        }
        return;
    }

    const button = document.querySelector('.composer-btn');
    const originalText = button.innerHTML;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Posting...';
    button.disabled = true;

    try {
        console.log('Creating post with content:', content);

        const response = await fetch(`/api/clubs/${mobileDashboard.clubId}/posts`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                content: content
            })
        });

        console.log('Post creation response status:', response.status);
        
        if (response.ok) {
            const data = await response.json();
            console.log('Post creation response data:', data);
            
            // Clear the textarea
            document.getElementById('mobilePostContent').value = '';
            
            if (mobileDashboard) {
                mobileDashboard.showToast('Post created successfully!', 'success');
                // Reload posts to show the new one
                await mobileDashboard.loadPosts();
                
                // If we're currently viewing stream, refresh the display
                if (mobileDashboard.currentSection === 'stream') {
                    await mobileDashboard.loadPosts();
                }
            }
        } else {
            const errorData = await response.json();
            console.error('Post creation failed:', errorData);
            throw new Error(errorData.error || 'Failed to create post');
        }
    } catch (error) {
        console.error('Error creating post:', error);
        if (mobileDashboard) {
            mobileDashboard.showToast(error.message || 'Failed to create post', 'error');
        }
    } finally {
        button.innerHTML = originalText;
        button.disabled = false;
    }
}

function confirmRemoveMember(userId, username) {
    console.log('Remove member functionality would be integrated here');
    if (mobileDashboard) {
        mobileDashboard.showToast('Remove member feature coming soon!', 'info');
    }
}

function loadHackatimeProjects() {
    if (mobileDashboard) {
        mobileDashboard.loadHackatimeProjects();
    }
}

function openCreateMeetingModal() {
    console.log('Create meeting modal would be integrated here');
    if (mobileDashboard) {
        mobileDashboard.showToast('Create meeting feature coming soon!', 'info');
    }
}

function openAddResourceModal() {
    console.log('Add resource modal would be integrated here');
    if (mobileDashboard) {
        mobileDashboard.showToast('Add resource feature coming soon!', 'info');
    }
}

function openCreateAssignmentModal() {
    openMobileModal('createAssignmentModal');
}

function openCreateMeetingModal() {
    openMobileModal('createMeetingModal');
}

function openAddResourceModal() {
    openMobileModal('addResourceModal');
}

function openPizzaGrantModal() {
    openMobileModal('pizzaGrantModal');
}

function openMobileModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
}

function closeMobileModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('active');
        document.body.style.overflow = '';
        
        // Clear form data
        const form = modal.querySelector('form');
        if (form) {
            form.reset();
        }
        
        // Reset any specific input fields that might not be in a form
        if (modalId === 'createAssignmentModal') {
            document.getElementById('mobileAssignmentTitle').value = '';
            document.getElementById('mobileAssignmentDescription').value = '';
            document.getElementById('mobileAssignmentDueDate').value = '';
            document.getElementById('mobileAssignmentForAll').checked = true;
        } else if (modalId === 'createMeetingModal') {
            document.getElementById('mobileMeetingTitle').value = '';
            document.getElementById('mobileMeetingDescription').value = '';
            document.getElementById('mobileMeetingDateTime').value = '';
            document.getElementById('mobileMeetingLocation').value = '';
            document.getElementById('mobileMeetingLink').value = '';
        } else if (modalId === 'addResourceModal') {
            document.getElementById('mobileResourceTitle').value = '';
            document.getElementById('mobileResourceDescription').value = '';
            document.getElementById('mobileResourceUrl').value = '';
            document.getElementById('mobileResourceIcon').value = '';
        }
    }
}

async function createMobileAssignment() {
    const title = document.getElementById('mobileAssignmentTitle').value.trim();
    const description = document.getElementById('mobileAssignmentDescription').value.trim();
    const dueDate = document.getElementById('mobileAssignmentDueDate').value;
    const forAll = document.getElementById('mobileAssignmentForAll').checked;

    if (!title || !description) {
        if (mobileDashboard) {
            mobileDashboard.showToast('Please fill in all required fields', 'error');
        }
        return;
    }

    const button = document.querySelector('#createAssignmentModal .mobile-btn-primary');
    const originalText = button.innerHTML;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating...';
    button.disabled = true;

    try {
        console.log('Creating assignment with data:', {
            title,
            description,
            due_date: dueDate || null,
            for_all_members: forAll
        });

        const response = await fetch(`/api/clubs/${mobileDashboard.clubId}/assignments`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                title,
                description,
                due_date: dueDate || null,
                for_all_members: forAll
            })
        });

        console.log('Assignment creation response status:', response.status);
        
        if (response.ok) {
            const data = await response.json();
            console.log('Assignment creation response data:', data);
            
            closeMobileModal('createAssignmentModal');
            if (mobileDashboard) {
                mobileDashboard.showToast('Assignment created successfully!', 'success');
                // Force reload the assignments section
                await mobileDashboard.loadAssignments();
                mobileDashboard.updateStats();
                
                // If we're currently viewing assignments, refresh the display
                if (mobileDashboard.currentSection === 'assignments') {
                    await mobileDashboard.loadAssignments();
                }
            }
        } else {
            const errorData = await response.json();
            console.error('Assignment creation failed:', errorData);
            throw new Error(errorData.error || 'Failed to create assignment');
        }
    } catch (error) {
        console.error('Error creating assignment:', error);
        if (mobileDashboard) {
            mobileDashboard.showToast(error.message || 'Failed to create assignment', 'error');
        }
    } finally {
        button.innerHTML = originalText;
        button.disabled = false;
    }
}

async function createMobileMeeting() {
    const title = document.getElementById('mobileMeetingTitle').value.trim();
    const description = document.getElementById('mobileMeetingDescription').value.trim();
    const datetime = document.getElementById('mobileMeetingDateTime').value;
    const location = document.getElementById('mobileMeetingLocation').value.trim();
    const link = document.getElementById('mobileMeetingLink').value.trim();

    if (!title || !datetime) {
        if (mobileDashboard) {
            mobileDashboard.showToast('Please fill in all required fields', 'error');
        }
        return;
    }

    // Parse datetime into date and time parts
    const datetimeObj = new Date(datetime);
    const date = datetimeObj.toISOString().split('T')[0]; // YYYY-MM-DD
    const startTime = datetimeObj.toTimeString().split(' ')[0].substring(0, 5); // HH:MM

    const button = document.querySelector('#createMeetingModal .mobile-btn-primary');
    const originalText = button.innerHTML;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scheduling...';
    button.disabled = true;

    try {
        console.log('Creating meeting with data:', {
            title,
            description,
            meeting_date: date,
            start_time: startTime,
            end_time: '',
            location,
            meeting_link: link
        });

        const response = await fetch(`/api/clubs/${mobileDashboard.clubId}/meetings`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                title,
                description,
                meeting_date: date,
                start_time: startTime,
                end_time: '', // Optional
                location,
                meeting_link: link
            })
        });

        console.log('Meeting creation response status:', response.status);
        
        if (response.ok) {
            const data = await response.json();
            console.log('Meeting creation response data:', data);
            
            closeMobileModal('createMeetingModal');
            if (mobileDashboard) {
                mobileDashboard.showToast('Meeting scheduled successfully!', 'success');
                // Force reload the meetings section
                await mobileDashboard.loadMeetings();
                mobileDashboard.updateStats();
                
                // If we're currently viewing schedule detail, refresh the display
                const scheduleDetail = document.getElementById('scheduleDetail');
                if (scheduleDetail && scheduleDetail.classList.contains('active')) {
                    await mobileDashboard.loadMeetings();
                }
            }
        } else {
            const errorData = await response.json();
            console.error('Meeting creation failed:', errorData);
            throw new Error(errorData.error || 'Failed to create meeting');
        }
    } catch (error) {
        console.error('Error creating meeting:', error);
        if (mobileDashboard) {
            mobileDashboard.showToast(error.message || 'Failed to schedule meeting', 'error');
        }
    } finally {
        button.innerHTML = originalText;
        button.disabled = false;
    }
}

async function addMobileResource() {
    const title = document.getElementById('mobileResourceTitle').value.trim();
    const description = document.getElementById('mobileResourceDescription').value.trim();
    const url = document.getElementById('mobileResourceUrl').value.trim();
    const icon = document.getElementById('mobileResourceIcon').value.trim() || 'link';

    if (!title || !url) {
        if (mobileDashboard) {
            mobileDashboard.showToast('Please fill in all required fields', 'error');
        }
        return;
    }

    const button = document.querySelector('#addResourceModal .mobile-btn-primary');
    const originalText = button.innerHTML;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Adding...';
    button.disabled = true;

    try {
        console.log('Creating resource with data:', {
            title,
            url,
            description,
            icon
        });

        const response = await fetch(`/api/clubs/${mobileDashboard.clubId}/resources`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                title,
                url,
                description,
                icon
            })
        });

        console.log('Resource creation response status:', response.status);
        
        if (response.ok) {
            const data = await response.json();
            console.log('Resource creation response data:', data);
            
            closeMobileModal('addResourceModal');
            if (mobileDashboard) {
                mobileDashboard.showToast('Resource added successfully!', 'success');
                // Force reload the resources section
                await mobileDashboard.loadResources();
                
                // If we're currently viewing resources detail, refresh the display
                const resourcesDetail = document.getElementById('resourcesDetail');
                if (resourcesDetail && resourcesDetail.classList.contains('active')) {
                    await mobileDashboard.loadResources();
                }
            }
        } else {
            const errorData = await response.json();
            console.error('Resource creation failed:', errorData);
            throw new Error(errorData.error || 'Failed to add resource');
        }
    } catch (error) {
        console.error('Error adding resource:', error);
        if (mobileDashboard) {
            mobileDashboard.showToast(error.message || 'Failed to add resource', 'error');
        }
    } finally {
        button.innerHTML = originalText;
        button.disabled = false;
    }
}

// Load Hackatime projects for selected member
async function loadMobileMemberHackatimeProjects() {
    const memberSelect = document.getElementById('mobileGrantMemberSelect');
    const projectSelect = document.getElementById('mobileGrantProjectSelect');
    const memberId = memberSelect.value;

    if (!memberId) {
        projectSelect.innerHTML = '<option value="">Select your project</option>';
        return;
    }

    projectSelect.innerHTML = '<option value="">Loading projects...</option>';

    try {
        const response = await fetch(`/api/hackatime/projects/${memberId}`);
        const data = await response.json();
        
        projectSelect.innerHTML = '<option value="">Select your project</option>';
        
        if (data.success && data.projects && data.projects.length > 0) {
            data.projects.forEach(project => {
                if (project.total_seconds >= 3600) { // At least 1 hour
                    const option = document.createElement('option');
                    option.value = JSON.stringify(project);
                    option.textContent = `${project.name} (${(project.total_seconds / 3600).toFixed(1)}h)`;
                    projectSelect.appendChild(option);
                }
            });
        } else {
            const option = document.createElement('option');
            option.value = '';
            option.textContent = 'No eligible projects found (minimum 1 hour)';
            option.disabled = true;
            projectSelect.appendChild(option);
        }
    } catch (error) {
        console.error('Error loading projects:', error);
        projectSelect.innerHTML = '<option value="">Error loading projects</option>';
    }
}

async function submitMobileGrant() {
    const projectSelect = document.getElementById('mobileGrantProjectSelect');
    let projectData = null;

    if (projectSelect.value) {
        try {
            projectData = JSON.parse(projectSelect.value);
        } catch (e) {
            if (mobileDashboard) {
                mobileDashboard.showToast('Invalid project selection', 'error');
            }
            return;
        }
    }

    // Handle screenshot upload first
    const screenshotFile = document.getElementById('mobileGrantScreenshot').files[0];
    if (!screenshotFile) {
        if (mobileDashboard) {
            mobileDashboard.showToast('Please upload a screenshot', 'error');
        }
        return;
    }

    // Show loading state
    const submitButton = document.querySelector('#pizzaGrantModal .mobile-btn-primary');
    const originalText = submitButton.innerHTML;
    submitButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Uploading...';
    submitButton.disabled = true;

    try {
        // Upload screenshot to CDN first
        const formData = new FormData();
        formData.append('screenshot', screenshotFile);

        const uploadResponse = await fetch('/api/upload-screenshot', {
            method: 'POST',
            body: formData
        });
        
        const uploadData = await uploadResponse.json();
        
        if (!uploadData.success) {
            throw new Error(uploadData.error || 'Failed to upload screenshot');
        }

        // Now submit the grant with the screenshot URL
        await submitMobileGrantWithScreenshot(uploadData.url, projectData, submitButton, originalText);

    } catch (error) {
        console.error('Error submitting grant:', error);
        if (mobileDashboard) {
            mobileDashboard.showToast(error.message || 'Failed to submit grant', 'error');
        }
        
        submitButton.innerHTML = originalText;
        submitButton.disabled = false;
    }
}

async function submitMobileGrantWithScreenshot(screenshotUrl, projectData, submitButton, originalText) {
    submitButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Submitting...';

    const formData = {
        member_id: document.getElementById('mobileGrantMemberSelect').value,
        project_name: projectData ? projectData.name : document.getElementById('mobileGrantProjectSelect').selectedOptions[0]?.text || '',
        project_hours: projectData ? (projectData.total_seconds / 3600).toFixed(2) : '0',
        first_name: document.getElementById('mobileGrantFirstName').value,
        last_name: document.getElementById('mobileGrantLastName').value,
        email: document.getElementById('mobileGrantEmail').value,
        birthday: document.getElementById('mobileGrantBirthday').value,
        project_description: document.getElementById('mobileGrantDescription').value,
        github_url: document.getElementById('mobileGrantGithubUrl').value,
        live_url: document.getElementById('mobileGrantLiveUrl').value,
        learning: document.getElementById('mobileGrantLearning').value,
        doing_well: document.getElementById('mobileGrantDoingWell').value,
        improve: document.getElementById('mobileGrantImprove').value,
        address_1: document.getElementById('mobileGrantAddress1').value,
        address_2: document.getElementById('mobileGrantAddress2').value,
        city: document.getElementById('mobileGrantCity').value,
        state: document.getElementById('mobileGrantState').value,
        zip: document.getElementById('mobileGrantZip').value,
        country: document.getElementById('mobileGrantCountry').value,
        screenshot_url: screenshotUrl
    };

    try {
        const response = await fetch(`/api/clubs/${mobileDashboard.clubId}/submit-grant`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        });

        const data = await response.json();

        if (data.success) {
            closeMobileModal('pizzaGrantModal');
            if (mobileDashboard) {
                mobileDashboard.showToast('Grant submitted successfully!', 'success');
                // Reset form
                document.getElementById('mobilePizzaGrantForm').reset();
                // Reload submissions if we're on the pizza detail section
                if (document.getElementById('pizzaDetail').style.display !== 'none') {
                    await mobileDashboard.loadSubmissions();
                }
            }
        } else {
            throw new Error(data.error || 'Failed to submit grant');
        }
    } catch (error) {
        console.error('Error submitting grant:', error);
        if (mobileDashboard) {
            mobileDashboard.showToast(error.message || 'Failed to submit grant', 'error');
        }
    } finally {
        submitButton.innerHTML = originalText;
        submitButton.disabled = false;
    }
}

function copyJoinCode() {
    const joinCodeInput = document.getElementById('modalJoinCode');
    if (joinCodeInput) {
        joinCodeInput.select();
        joinCodeInput.setSelectionRange(0, 99999); // For mobile devices
        
        try {
            document.execCommand('copy');
            if (mobileDashboard) {
                mobileDashboard.showToast('Join code copied!', 'success');
            }
        } catch (err) {
            console.error('Failed to copy join code:', err);
            if (mobileDashboard) {
                mobileDashboard.showToast('Failed to copy join code', 'error');
            }
        }
    }
}

function copyJoinUrl() {
    const joinUrlInput = document.getElementById('joinUrl');
    if (joinUrlInput) {
        joinUrlInput.select();
        joinUrlInput.setSelectionRange(0, 99999); // For mobile devices
        
        try {
            document.execCommand('copy');
            if (mobileDashboard) {
                mobileDashboard.showToast('Join URL copied!', 'success');
            }
        } catch (err) {
            console.error('Failed to copy join URL:', err);
            if (mobileDashboard) {
                mobileDashboard.showToast('Failed to copy join URL', 'error');
            }
        }
    }
}

async function shareClub() {
    const joinCode = mobileDashboard?.joinCode;
    const joinUrl = `${window.location.origin}/join-club?code=${joinCode}`;
    
    if (navigator.share) {
        try {
            await navigator.share({
                title: 'Join my Hack Club!',
                text: `Join my club with code: ${joinCode}`,
                url: joinUrl
            });
            if (mobileDashboard) {
                mobileDashboard.showToast('Shared successfully!', 'success');
            }
        } catch (err) {
            console.error('Error sharing:', err);
            // Fallback to copying the URL
            copyJoinUrl();
        }
    } else {
        // Fallback for browsers that don't support Web Share API
        copyJoinUrl();
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    mobileDashboard = new MobileClubDashboard();
});

// Handle page visibility changes for better performance
document.addEventListener('visibilitychange', () => {
    if (!document.hidden && mobileDashboard) {
        mobileDashboard.refreshData();
    }
});