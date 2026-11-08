"""
SecureVault - UI Theme & Stylesheet (Dark Mode)
Modern navy/slate dark theme with electric blue and cyan accents,
glassmorphism cards, rounded corners, and consistent typography.
"""

DARK_THEME_QSS = """
/* Global Window & Font Settings */
QWidget {
    background-color: #0b1120;
    color: #f1f5f9;
    font-family: 'Segoe UI', 'SF Pro Display', -apple-system, sans-serif;
    font-size: 13px;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
}

/* Card Containers */
QFrame#Card, QWidget#Card {
    background-color: #131d31;
    border: 1px solid #1e293b;
    border-radius: 12px;
}

QFrame#CardHighlight {
    background-color: #17243d;
    border: 1px solid #3b82f6;
    border-radius: 12px;
}

/* Sidebar Navigation */
QFrame#Sidebar {
    background-color: #070d19;
    border-right: 1px solid #1e293b;
}

QPushButton#NavBtn {
    background-color: transparent;
    color: #94a3b8;
    text-align: left;
    padding: 12px 18px;
    border: none;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 600;
}

QPushButton#NavBtn:hover {
    background-color: #1e293b;
    color: #38bdf8;
}

QPushButton#NavBtn:checked, QPushButton#NavBtnActive {
    background-color: #1d4ed8;
    color: #ffffff;
    font-weight: bold;
}

/* Primary Action Buttons */
QPushButton#PrimaryBtn {
    background-color: #2563eb;
    color: #ffffff;
    border: none;
    border-radius: 8px;
    padding: 10px 20px;
    font-size: 13px;
    font-weight: 600;
}

QPushButton#PrimaryBtn:hover {
    background-color: #3b82f6;
}

QPushButton#PrimaryBtn:pressed {
    background-color: #1d4ed8;
}

/* Secondary & Action Buttons */
QPushButton#SecondaryBtn {
    background-color: #1e293b;
    color: #e2e8f0;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 10px 18px;
    font-weight: 500;
}

QPushButton#SecondaryBtn:hover {
    background-color: #334155;
    border-color: #475569;
}

QPushButton#SuccessBtn {
    background-color: #059669;
    color: #ffffff;
    border: none;
    border-radius: 8px;
    padding: 10px 18px;
    font-weight: 600;
}

QPushButton#SuccessBtn:hover {
    background-color: #10b981;
}

QPushButton#DangerBtn {
    background-color: #dc2626;
    color: #ffffff;
    border: none;
    border-radius: 8px;
    padding: 10px 18px;
    font-weight: 600;
}

QPushButton#DangerBtn:hover {
    background-color: #ef4444;
}

/* Text Inputs and TextEdits */
QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #0f172a;
    color: #f8fafc;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 8px 12px;
}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border: 1px solid #38bdf8;
    background-color: #0f1c34;
}

/* Labels */
QLabel {
    color: #f1f5f9;
}

QLabel#TitleLabel {
    font-size: 20px;
    font-weight: bold;
    color: #f8fafc;
}

QLabel#SubtitleLabel {
    font-size: 13px;
    color: #94a3b8;
}

QLabel#SectionHeader {
    font-size: 15px;
    font-weight: 600;
    color: #38bdf8;
}

QLabel#BadgeSuccess {
    background-color: rgba(16, 185, 129, 0.15);
    color: #34d399;
    border: 1px solid #059669;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: bold;
}

QLabel#BadgeWarning {
    background-color: rgba(245, 158, 11, 0.15);
    color: #fbbf24;
    border: 1px solid #d97706;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: bold;
}

QLabel#BadgeInfo {
    background-color: rgba(56, 189, 248, 0.15);
    color: #38bdf8;
    border: 1px solid #0284c7;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: bold;
}

/* Tables */
QTableWidget, QTableView {
    background-color: #0f172a;
    alternate-background-color: #131d31;
    border: 1px solid #1e293b;
    border-radius: 8px;
    gridline-color: #1e293b;
    color: #f1f5f9;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
}

QHeaderView::section {
    background-color: #17243d;
    color: #94a3b8;
    padding: 8px;
    border: none;
    border-bottom: 2px solid #2563eb;
    font-weight: bold;
}

/* Scrollbars */
QScrollBar:vertical {
    border: none;
    background-color: #0b1120;
    width: 8px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background-color: #334155;
    min-height: 20px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background-color: #475569;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

/* Tab Widget */
QTabWidget::pane {
    border: 1px solid #1e293b;
    background-color: #131d31;
    border-radius: 8px;
}

QTabBar::tab {
    background-color: #0f172a;
    color: #94a3b8;
    padding: 10px 20px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    margin-right: 4px;
    font-weight: 600;
}

QTabBar::tab:selected {
    background-color: #131d31;
    color: #38bdf8;
    border-bottom: 2px solid #38bdf8;
}

/* Progress Bar */
QProgressBar {
    border: 1px solid #334155;
    border-radius: 6px;
    background-color: #0f172a;
    text-align: center;
    color: #ffffff;
    font-weight: bold;
}

QProgressBar::chunk {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2563eb, stop:1 #06b6d4);
    border-radius: 5px;
}

/* Combo Box */
QComboBox {
    background-color: #0f172a;
    color: #f8fafc;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 8px 12px;
}

QComboBox::drop-down {
    border: none;
    width: 24px;
}

QComboBox QAbstractItemView {
    background-color: #131d31;
    color: #f8fafc;
    selection-background-color: #2563eb;
    border: 1px solid #334155;
}
"""
