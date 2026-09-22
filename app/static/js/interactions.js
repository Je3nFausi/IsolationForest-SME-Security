/**
 * BI-Safe Interactive Features
 * =============================
 * Adds fun, animated interactions to the dashboard.
 */

// ============================================================
// 1. NUMBER COUNT-UP ANIMATION
// ============================================================

function animateValue(element, start, end, duration = 1500) {
    const range = end - start;
    const increment = range / (duration / 16);
    let current = start;

    const timer = setInterval(() => {
        current += increment;
        if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
            element.textContent = Math.round(end);
            clearInterval(timer);
        } else {
            element.textContent = Math.round(current);
        }
    }, 16);
}

function initCountUp() {
    const statValues = document.querySelectorAll('.stat-card-value');

    statValues.forEach(el => {
        // Extract the numeric part from the text
        const text = el.textContent.trim();
        const match = text.match(/^(\d+)/);

        if (match) {
            const endValue = parseInt(match[1]);
            const suffix = text.replace(match[1], '');

            // Store the suffix
            el.dataset.suffix = suffix;
            el.textContent = '0' + suffix;

            // Animate when the element scrolls into view
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        animateValue(el, 0, endValue, 1500);
                        setTimeout(() => {
                            el.textContent = endValue + el.dataset.suffix;
                        }, 1550);
                        observer.unobserve(entry.target);
                    }
                });
            }, { threshold: 0.5 });

            observer.observe(el);
        }
    });
}

// ============================================================
// 2. CONFETTI CELEBRATION
// ============================================================

function triggerConfetti() {
    const container = document.createElement('div');
    container.className = 'confetti-container';
    document.body.appendChild(container);

    const colors = ['#e6ff2c', '#c8b8e8', '#4ade80', '#fb923c', '#f43f5e', '#ffffff'];

    for (let i = 0; i < 80; i++) {
        const piece = document.createElement('div');
        piece.className = 'confetti-piece';
        piece.style.left = Math.random() * 100 + '%';
        piece.style.backgroundColor = colors[Math.floor(Math.random() * colors.length)];
        piece.style.animationDelay = Math.random() * 0.5 + 's';
        piece.style.animationDuration = (2 + Math.random() * 2) + 's';

        // Random shapes
        if (Math.random() > 0.5) {
            piece.style.borderRadius = '50%';
        } else {
            piece.style.width = '6px';
            piece.style.height = '14px';
        }

        container.appendChild(piece);
    }

    setTimeout(() => {
        container.remove();
    }, 4000);
}

// ============================================================
// 3. ANIMATED TOAST
// ============================================================

function showToast(message, type = 'success') {
    let toast = document.getElementById('toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'toast';
        document.body.appendChild(toast);
    }

    const colors = {
        success: '#e6ff2c',
        error: '#f43f5e',
        info: '#c8b8e8',
        warning: '#fb923c'
    };

    toast.textContent = message;
    toast.style.background = colors[type] || colors.success;
    toast.style.color = type === 'error' ? '#ffffff' : '#000000';
    toast.style.display = 'block';

    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => {
        toast.style.display = 'none';
    }, 3500);

    // Trigger confetti for success
    if (type === 'success') {
        triggerConfetti();
    }
}

// ============================================================
// 4. BUTTON RIPPLE EFFECT
// ============================================================

function initRippleEffect() {
    document.querySelectorAll('.btn').forEach(btn => {
        btn.addEventListener('click', function (e) {
            const rect = this.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;

            const ripple = document.createElement('span');
            ripple.style.cssText = `
                position: absolute;
                width: 20px;
                height: 20px;
                background: rgba(255, 255, 255, 0.5);
                border-radius: 50%;
                transform: translate(-50%, -50%) scale(0);
                animation: rippleEffect 0.6s ease-out;
                left: ${x}px;
                top: ${y}px;
                pointer-events: none;
            `;

            this.appendChild(ripple);
            setTimeout(() => ripple.remove(), 600);
        });
    });
}

// Add ripple keyframes dynamically
const rippleStyle = document.createElement('style');
rippleStyle.textContent = `
    @keyframes rippleEffect {
        to {
            transform: translate(-50%, -50%) scale(15);
            opacity: 0;
        }
    }
`;
document.head.appendChild(rippleStyle);

// ============================================================
// 5. HOVER TILT EFFECT ON CARDS
// ============================================================

function initCardTilt() {
    document.querySelectorAll('.stat-card').forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = (e.clientX - rect.left) / rect.width - 0.5;
            const y = (e.clientY - rect.top) / rect.height - 0.5;

            card.style.transform = `
                translateY(-6px)
                rotateX(${-y * 4}deg)
                rotateY(${x * 4}deg)
            `;
        });

        card.addEventListener('mouseleave', () => {
            card.style.transform = '';
        });
    });
}

// ============================================================
// 6. LIVE STATUS INDICATOR
// ============================================================

function initLiveIndicator() {
    const statusElements = document.querySelectorAll('[data-live-status]');

    statusElements.forEach(el => {
        if (el.textContent.toLowerCase().includes('running')) {
            const dot = document.createElement('span');
            dot.className = 'live-indicator';
            el.prepend(dot);
        }
    });
}

// ============================================================
// 7. TYPEWRITER EFFECT ON PAGE TITLES
// ============================================================

function initTypewriter() {
    const titles = document.querySelectorAll('[data-typewriter]');

    titles.forEach(title => {
        const text = title.textContent;
        title.textContent = '';
        title.style.borderRight = '3px solid #e6ff2c';

        let i = 0;
        const timer = setInterval(() => {
            if (i < text.length) {
                title.textContent += text.charAt(i);
                i++;
            } else {
                clearInterval(timer);
                setTimeout(() => {
                    title.style.borderRight = 'none';
                }, 500);
            }
        }, 50);
    });
}

// ============================================================
// 8. PAGE LOAD PROGRESS BAR
// ============================================================

function initProgressBar() {
    const bar = document.createElement('div');
    bar.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        height: 3px;
        background: linear-gradient(90deg, #e6ff2c, #c8b8e8);
        z-index: 999999;
        transition: width 0.4s ease;
        width: 0;
    `;
    document.body.appendChild(bar);

    let progress = 0;
    const interval = setInterval(() => {
        progress += Math.random() * 30;
        if (progress >= 100) {
            progress = 100;
            bar.style.width = '100%';
            clearInterval(interval);
            setTimeout(() => {
                bar.style.opacity = '0';
                setTimeout(() => bar.remove(), 300);
            }, 300);
        } else {
            bar.style.width = progress + '%';
        }
    }, 150);
}

// ============================================================
// 9. SMOOTH SCROLL TO ELEMENTS
// ============================================================

function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                e.preventDefault();
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });
}

// ============================================================
// 10. FLOATING NOTIFICATION BADGE
// ============================================================

function initNotificationPulse() {
    const alertsLinks = document.querySelectorAll('[data-alerts-badge]');

    alertsLinks.forEach(link => {
        const badge = document.createElement('span');
        badge.style.cssText = `
            display: inline-block;
            width: 8px;
            height: 8px;
            background: #f43f5e;
            border-radius: 50%;
            margin-left: 6px;
            animation: pulse 1.5s infinite;
        `;
        link.appendChild(badge);
    });
}

// ============================================================
// INITIALIZE ALL
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
    initProgressBar();
    initCountUp();
    initRippleEffect();
    initCardTilt();
    initLiveIndicator();
    initTypewriter();
    initSmoothScroll();
    initNotificationPulse();
});