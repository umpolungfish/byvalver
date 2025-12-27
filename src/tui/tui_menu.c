#include "tui_menu.h"
#include "tui_screens.h"
#include "tui_config_builder.h"
#include <string.h>
#include <stdlib.h>

// Function to run the interactive TUI menu
int run_tui_menu(byvalver_config_t *config) {
    // Initialize the TUI environment
    if (init_tui() != 0) {
        return -1;
    }

    int result = 0;
    int current_screen = MAIN_SCREEN;

    while (1) {
        switch (current_screen) {
            case MAIN_SCREEN:
                current_screen = show_main_screen(config);
                break;

            case INPUT_SCREEN:
                current_screen = show_input_screen(config);
                break;

            case OPTIONS_SCREEN:
                current_screen = show_options_screen(config);
                break;

            case PROCESSING_SCREEN:
                current_screen = show_processing_screen(config);
                break;

            case RESULTS_SCREEN:
                current_screen = show_results_screen(config);
                break;

            case CONFIG_SCREEN:
                current_screen = show_config_screen(config);
                break;

            case BAD_CHARS_SCREEN:
                current_screen = show_bad_chars_screen(config);
                break;

            case BATCH_SCREEN:
                current_screen = show_batch_screen(config);
                break;

            case ML_METRICS_SCREEN:
                current_screen = show_ml_metrics_screen(config);
                break;

            case OUTPUT_FORMAT_SCREEN:
                current_screen = show_output_format_screen(config);
                break;

            case ADVANCED_OPTIONS_SCREEN:
                current_screen = show_advanced_options_screen(config);
                break;

            case ABOUT_SCREEN:
                current_screen = show_about_screen();
                break;

            case EXIT_SCREEN:
                cleanup_tui();
                return result;

            default:
                // Invalid screen, exit
                cleanup_tui();
                return -1;
        }
    }
    
    cleanup_tui();
    return result;
}

// Function to initialize ncurses and set up the TUI environment
int init_tui() {
    // Initialize ncurses
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    start_color();
    init_pair(1, COLOR_WHITE, COLOR_BLUE);    // Main header
    init_pair(2, COLOR_BLACK, COLOR_WHITE);   // Menu items
    init_pair(3, COLOR_WHITE, COLOR_RED);     // Error messages
    init_pair(4, COLOR_GREEN, COLOR_BLACK);   // Success messages
    init_pair(5, COLOR_YELLOW, COLOR_BLACK);  // Warnings
    
    // Clear the screen
    clear();
    refresh();
    
    return 0;
}

// Function to clean up ncurses and restore terminal settings
void cleanup_tui() {
    endwin();
}