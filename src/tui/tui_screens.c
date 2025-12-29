#define _GNU_SOURCE  // Required for strdup function
#include "tui_screens.h"
#include "tui_file_browser.h"  // Include file browser header
#include "tui_config_builder.h"  // Include config builder for save/load/reset
#include "../badchar_profiles.h"  // Include bad character profiles header
#include "../processing.h"  // Include processing function header
#include "../core.h"  // Include core functions
#include "../strategy.h"  // Include strategy initialization
#include "../obfuscation_strategy_registry.h"  // Include obfuscation strategies
#include "../batch_processing.h"  // Include batch processing
#include <string.h>
#include <stdlib.h>
#include <unistd.h>  // For napms function and dup/dup2
#include <errno.h>
#include <sys/stat.h>  // For stat() and struct stat
#include <fcntl.h>  // For open() and O_WRONLY

// Global variables to store processing results
static size_t g_last_input_size = 0;
static size_t g_last_output_size = 0;
static int g_last_processing_result = -1;

// Draw the main menu in the left panel
void draw_main_menu(byvalver_config_t *config, int current_selection) {
    (void)config; // May use config later for status indicators

    int row = 3;
    mvprintw(row++, 2, "byvalver v3.0");
    mvprintw(row++, 2, "-----------------------------------------");
    row++; // empty line
    mvprintw(row++, 2, "Main Menu:");
    row++; // empty line

    draw_menu_item(row++, 2, "1. Process Single File", current_selection == 1);
    draw_menu_item(row++, 2, "2. Batch Process Directory", current_selection == 2);
    draw_menu_item(row++, 2, "3. Processing Options", current_selection == 3);
    draw_menu_item(row++, 2, "4. Bad Characters", current_selection == 4);
    draw_menu_item(row++, 2, "5. Output Format", current_selection == 5);
    draw_menu_item(row++, 2, "6. ML Metrics", current_selection == 6);
    draw_menu_item(row++, 2, "7. Advanced Options", current_selection == 7);
    draw_menu_item(row++, 2, "8. Load/Save Config", current_selection == 8);
    draw_menu_item(row++, 2, "9. About", current_selection == 9);
    row++; // empty line
    draw_menu_item(row++, 2, "0. Exit", current_selection == 0);
    row++; // empty line
    mvprintw(row++, 2, "-----------------------------------------");

    attron(COLOR_PAIR(5));
    row++; // empty line
    mvprintw(row++, 2, "Navigation:");
    mvprintw(row++, 2, "  Up/Down or j/k - Navigate");
    mvprintw(row++, 2, "  Enter or # - Select");
    mvprintw(row++, 2, "  q - Quit");
    attroff(COLOR_PAIR(5));
}

// Main screen implementation with split-panel design
int show_main_screen(byvalver_config_t *config) {
    int main_selection = 1;
    int active_screen = MAIN_SCREEN;
    int sub_selection = 0;

    while(1) {
        // Draw everything
        clear_screen();
        draw_header("byvalver - Interactive Shellcode Processor");

        // Draw left panel (main menu)
        draw_main_menu(config, main_selection);

        // Draw vertical separator
        draw_vertical_separator();

        // Draw right panel based on current selection
        if (active_screen != MAIN_SCREEN && active_screen != PROCESSING_SCREEN) {
            int result = -1;
            switch (main_selection) {
                case 1:
                    result = show_input_screen(config, &sub_selection);
                    break;
                case 2:
                    result = show_batch_screen(config, &sub_selection);
                    break;
                case 3:
                    result = show_options_screen(config, &sub_selection);
                    break;
                case 4:
                    result = show_bad_chars_screen(config, &sub_selection);
                    break;
                case 5:
                    result = show_output_format_screen(config, &sub_selection);
                    break;
                case 6:
                    result = show_ml_metrics_screen(config, &sub_selection);
                    break;
                case 7:
                    result = show_advanced_options_screen(config, &sub_selection);
                    break;
                case 8:
                    result = show_config_screen(config, &sub_selection);
                    break;
                case 9:
                    result = show_about_screen();
                    break;
            }

            // If sub-screen wants to exit, clear right panel and redraw
            if (result == MAIN_SCREEN || result == RESULTS_SCREEN) {
                // Processing completed or screen wants to return to main
                active_screen = MAIN_SCREEN;
                sub_selection = 0;
                clear_screen();  // Force screen refresh
                continue;
            } else if (result == PROCESSING_SCREEN) {
                // Processing needs full screen - call it and handle result
                int proc_result = show_processing_screen(config);
                if (proc_result == RESULTS_SCREEN || proc_result == MAIN_SCREEN) {
                    // After processing, return to main menu
                    active_screen = MAIN_SCREEN;
                    sub_selection = 0;
                    clear_screen();
                    continue;
                } else if (proc_result == EXIT_SCREEN) {
                    // User wants to exit
                    return EXIT_SCREEN;
                }
                // Fallback: any other result goes to main screen
                active_screen = MAIN_SCREEN;
                sub_selection = 0;
                clear_screen();
                continue;
            } else if (result == EXIT_SCREEN) {
                // Explicit exit request
                return EXIT_SCREEN;
            }
            // For any other result (like -1 from most screens), just continue the loop
        } else {
            // Show welcome message on right panel
            clear_right_panel();
            draw_right_panel_header("Welcome");

            int row = 5;
            int col = RIGHT_PANEL_START + 2;

            // Display ASCII art banner
            attron(COLOR_PAIR(4) | A_BOLD);
            mvprintw(row++, col, "8                           8                     ");
            mvprintw(row++, col, "8                           8                     ");
            mvprintw(row++, col, "8oPYo. o    o o    o .oPYo. 8 o    o .oPYo. oPYo. ");
            mvprintw(row++, col, "8    8 8    8 Y.  .P .oooo8 8 Y.  .P 8oooo8 8  `' ");
            mvprintw(row++, col, "8    8 8    8 `b..d' 8    8 8 `b..d' 8.     8     ");
            mvprintw(row++, col, "`YooP' `YooP8  `YP'  `YooP8 8  `YP'  `Yooo' 8     ");
            attroff(COLOR_PAIR(4) | A_BOLD);
            attron(COLOR_PAIR(5));
            mvprintw(row++, col, ":.....::....8 ::...:::.....:..::...:::.....:..::::");
            mvprintw(row++, col, ":::::::::ooP'.::::::::::::::::::::::::::::::::::::");
            mvprintw(row++, col, ":::::::::...:::::::::::::::::::::::::::::::::::::::");
            attroff(COLOR_PAIR(5));

            row++; // empty line
            row++; // empty line

            attron(A_BOLD);
            mvprintw(row++, col, "Welcome to byvalver!");
            attroff(A_BOLD);
            row++; // empty line
            mvprintw(row++, col, "Select an option from the menu on the left");
            mvprintw(row++, col, "to configure and process shellcode.");
            row++; // empty line

            attron(COLOR_PAIR(4));
            mvprintw(row++, col, "Quick Start:");
            attroff(COLOR_PAIR(4));
            mvprintw(row++, col, "  1. Set bad characters (optional)");
            mvprintw(row++, col, "  2. Select input/output file");
            mvprintw(row++, col, "  3. Configure processing options");
            mvprintw(row++, col, "  4. Start processing");
        }

        draw_footer();
        refresh();

        // Handle input
        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            return EXIT_SCREEN;
        } else if (ch == 27 || ch == KEY_LEFT) {  // ESC or Left arrow
            // Return to welcome screen
            active_screen = MAIN_SCREEN;
            sub_selection = 0;
        } else if (ch == KEY_UP || ch == 'k' || ch == 'K') {
            if (active_screen != MAIN_SCREEN && active_screen != PROCESSING_SCREEN) {
                // Navigate within sub-screen
                if (sub_selection > 1) {
                    sub_selection--;
                }
            } else {
                // Navigate main menu
                if (main_selection > 0) {
                    main_selection--;
                } else {
                    main_selection = 9;
                }
            }
        } else if (ch == KEY_DOWN || ch == 'j' || ch == 'J') {
            if (active_screen != MAIN_SCREEN && active_screen != PROCESSING_SCREEN) {
                // Navigate within sub-screen (with bounds checking)
                int max_selection = 5;  // Default
                if (active_screen == INPUT_SCREEN) max_selection = 4;
                if (active_screen == BATCH_SCREEN) max_selection = 8;
                if (active_screen == OPTIONS_SCREEN) max_selection = 5;
                if (active_screen == BAD_CHARS_SCREEN) max_selection = 5;
                if (active_screen == OUTPUT_FORMAT_SCREEN) max_selection = 5;
                if (active_screen == ML_METRICS_SCREEN) max_selection = 4;
                if (active_screen == ADVANCED_OPTIONS_SCREEN) max_selection = 3;
                if (active_screen == CONFIG_SCREEN) max_selection = 3;
                if (sub_selection < max_selection) {
                    sub_selection++;
                }
            } else {
                // Navigate main menu
                if (main_selection < 9) {
                    main_selection++;
                } else {
                    main_selection = 0;
                }
            }
        } else if (ch == '\n' || ch == '\r' || ch == ' ') {
            if (active_screen == MAIN_SCREEN || active_screen == PROCESSING_SCREEN) {
                // Activating from main menu
                if (main_selection == 0) {
                    return EXIT_SCREEN;
                } else {
                    // Activate the selected screen in right panel
                    // Map menu numbers to screen IDs
                    switch (main_selection) {
                        case 1: active_screen = INPUT_SCREEN; break;
                        case 2: active_screen = BATCH_SCREEN; break;
                        case 3: active_screen = OPTIONS_SCREEN; break;
                        case 4: active_screen = BAD_CHARS_SCREEN; break;
                        case 5: active_screen = OUTPUT_FORMAT_SCREEN; break;
                        case 6: active_screen = ML_METRICS_SCREEN; break;
                        case 7: active_screen = ADVANCED_OPTIONS_SCREEN; break;
                        case 8: active_screen = CONFIG_SCREEN; break;
                        case 9: active_screen = ABOUT_SCREEN; break;
                        default: active_screen = MAIN_SCREEN; break;
                    }
                    sub_selection = 1;
                }
            } else {
                // Apply action in sub-screen (handled per screen)
                if (active_screen == INPUT_SCREEN) {
                    if (sub_selection == 1) {
                        // Browse for input file
                        char *selected = show_file_browser(config->input_file, BROWSER_MODE_SELECT_FILE, NULL);
                        if (selected) {
                            config->input_file = selected;  // show_file_browser returns strdup'd string
                        }
                    } else if (sub_selection == 2) {
                        // Browse for output file
                        char *selected = show_file_browser(config->output_file, BROWSER_MODE_SELECT_BOTH, NULL);
                        if (selected) {
                            config->output_file = selected;
                        }
                    } else if (sub_selection == 3) {
                        // Manual path entry
                        char filepath[512] = "";
                        int input_row = LINES - 3;
                        int which = 0;  // 0 = cancelled, 1 = input, 2 = output

                        clear_right_panel();
                        draw_right_panel_header("Enter File Paths");
                        mvprintw(5, RIGHT_PANEL_START + 2, "Which file to set?");
                        mvprintw(7, RIGHT_PANEL_START + 2, "1 - Input File");
                        mvprintw(8, RIGHT_PANEL_START + 2, "2 - Output File");
                        mvprintw(9, RIGHT_PANEL_START + 2, "ESC - Cancel");
                        refresh();

                        int ch2 = getch();
                        if (ch2 == '1') which = 1;
                        else if (ch2 == '2') which = 2;

                        if (which > 0) {
                            clear_right_panel();
                            draw_right_panel_header(which == 1 ? "Set Input File" : "Set Output File");
                            mvprintw(input_row, RIGHT_PANEL_START + 2, "Enter path: ");
                            echo();
                            curs_set(1);
                            getnstr(filepath, sizeof(filepath) - 1);
                            curs_set(0);
                            noecho();

                            if (strlen(filepath) > 0) {
                                if (which == 1) {
                                    config->input_file = strdup(filepath);
                                } else {
                                    config->output_file = strdup(filepath);
                                }
                            }
                        }
                    } else if (sub_selection == 4) {
                        // Start processing
                        if (config->input_file) {
                            int proc_result = show_processing_screen(config);
                            if (proc_result == RESULTS_SCREEN || proc_result == MAIN_SCREEN) {
                                // Processing completed - return to main menu
                                active_screen = MAIN_SCREEN;
                                sub_selection = 0;
                                continue;
                            } else if (proc_result == EXIT_SCREEN) {
                                // User wants to exit
                                return EXIT_SCREEN;
                            }
                            // Fallback: return to main menu for any other result
                            active_screen = MAIN_SCREEN;
                            sub_selection = 0;
                            continue;
                        }
                    }
                } else if (active_screen == BATCH_SCREEN) {
                    if (sub_selection >= 1 && sub_selection <= 8) {
                        if (sub_selection == 1) {
                            // Browse Input Directory
                            char *selected = show_file_browser(config->input_file, BROWSER_MODE_SELECT_DIRECTORY, NULL);
                            if (selected) {
                                config->input_file = selected;
                            }
                        } else if (sub_selection == 2) {
                            // Browse Output Directory
                            char *selected = show_file_browser(config->output_file, BROWSER_MODE_SELECT_DIRECTORY, NULL);
                            if (selected) {
                                config->output_file = selected;
                            }
                        } else if (sub_selection == 3) {
                            // Manual path entry
                            char filepath[512] = "";
                            int input_row = LINES - 3;
                            int which = 0;  // 0 = cancelled, 1 = input, 2 = output

                            clear_right_panel();
                            draw_right_panel_header("Enter Directory Paths");
                            mvprintw(5, RIGHT_PANEL_START + 2, "Which directory to set?");
                            mvprintw(7, RIGHT_PANEL_START + 2, "1 - Input Directory");
                            mvprintw(8, RIGHT_PANEL_START + 2, "2 - Output Directory");
                            mvprintw(9, RIGHT_PANEL_START + 2, "ESC - Cancel");
                            refresh();

                            int ch2 = getch();
                            if (ch2 == '1') which = 1;
                            else if (ch2 == '2') which = 2;

                            if (which > 0) {
                                clear_right_panel();
                                draw_right_panel_header(which == 1 ? "Set Input Directory" : "Set Output Directory");
                                mvprintw(input_row, RIGHT_PANEL_START + 2, "Enter path: ");
                                echo();
                                curs_set(1);
                                getnstr(filepath, sizeof(filepath) - 1);
                                curs_set(0);
                                noecho();

                                if (strlen(filepath) > 0) {
                                    if (which == 1) {
                                        config->input_file = strdup(filepath);
                                    } else {
                                        config->output_file = strdup(filepath);
                                    }
                                }
                            }
                        } else if (sub_selection == 4) {
                            // Set File Pattern
                            char pattern[128] = "";
                            int input_row = LINES - 3;

                            clear_right_panel();
                            draw_right_panel_header("Set File Pattern");
                            mvprintw(input_row, RIGHT_PANEL_START + 2, "Enter pattern (e.g., *.bin): ");
                            echo();
                            curs_set(1);
                            getnstr(pattern, sizeof(pattern) - 1);
                            curs_set(0);
                            noecho();

                            if (strlen(pattern) > 0) {
                                config->file_pattern = strdup(pattern);
                            }
                        } else if (sub_selection == 5) {
                            // Toggle Recursive Mode
                            config->recursive = !config->recursive;
                        } else if (sub_selection == 6) {
                            // Toggle Continue on Error
                            config->continue_on_error = !config->continue_on_error;
                        } else if (sub_selection == 7) {
                            // Toggle Preserve Dir Structure
                            config->preserve_structure = !config->preserve_structure;
                        } else if (sub_selection == 8) {
                            // Start Batch Processing
                            if (config->input_file && config->output_file) {
                                config->batch_mode = 1;
                                // The batch processing is handled in processing screen
                                int proc_result = show_processing_screen(config);
                                if (proc_result == RESULTS_SCREEN || proc_result == MAIN_SCREEN) {
                                    // Processing completed - return to main menu
                                    active_screen = MAIN_SCREEN;
                                    sub_selection = 0;
                                    continue;
                                } else if (proc_result == EXIT_SCREEN) {
                                    // User wants to exit
                                    return EXIT_SCREEN;
                                }
                                // Fallback: return to main menu for any other result
                                active_screen = MAIN_SCREEN;
                                sub_selection = 0;
                                continue;
                            } else {
                                // Show error message
                                clear_right_panel();
                                draw_right_panel_header("Batch Processing");
                                attron(COLOR_PAIR(3));
                                mvprintw(5, RIGHT_PANEL_START + 2, "Error: Input and output directories must be set!");
                                attroff(COLOR_PAIR(3));
                                mvprintw(7, RIGHT_PANEL_START + 2, "Press any key to continue...");
                                refresh();
                                getch();
                            }
                        }
                    }
                } else if (active_screen == OPTIONS_SCREEN) {
                    if (sub_selection >= 1 && sub_selection <= 5) {
                        switch (sub_selection) {
                            case 1: config->use_biphasic = !config->use_biphasic; break;
                            case 2: config->use_pic_generation = !config->use_pic_generation; break;
                            case 3: config->use_ml_strategist = !config->use_ml_strategist; break;
                            case 4: config->verbose = !config->verbose; break;
                            case 5: config->dry_run = !config->dry_run; break;
                        }
                    }
                } else if (active_screen == OUTPUT_FORMAT_SCREEN) {
                    const char *formats[] = {"raw", "c", "python", "powershell", "hexstring"};
                    if (sub_selection >= 1 && sub_selection <= 5) {
                        // Note: Don't free - output_format may point to static string from initialization
                        config->output_format = strdup(formats[sub_selection - 1]);
                    }
                } else if (active_screen == ADVANCED_OPTIONS_SCREEN) {
                    if (sub_selection >= 1 && sub_selection <= 3) {
                        switch (sub_selection) {
                            case 1: config->encode_shellcode = !config->encode_shellcode; break;
                            case 2: config->show_stats = !config->show_stats; break;
                            case 3: config->validate_output = !config->validate_output; break;
                        }
                    }
                } else if (active_screen == BAD_CHARS_SCREEN) {
                    if (sub_selection >= 1 && sub_selection <= 5) {
                        // Ensure bad_chars is initialized
                        if (!config->bad_chars) {
                            config->bad_chars = calloc(1, sizeof(bad_char_config_t));
                        }

                        if (sub_selection == 1) {
                            // Load Profile - arrow-key navigation
                            init_badchar_profiles();
                            int selected_profile = 0;
                            int done = 0;

                            while (!done) {
                                clear_right_panel();
                                draw_right_panel_header("Select Bad Character Profile");
                                int prof_row = 5;
                                int prof_col = RIGHT_PANEL_START + 2;

                                mvprintw(prof_row++, prof_col, "Arrow keys/j/k to navigate, Enter to select, ESC to cancel");
                                prof_row++;

                                for (size_t i = 0; i < NUM_PROFILES; i++) {
                                    const badchar_profile_t *profile = &BADCHAR_PROFILES[i];
                                    if ((int)i == selected_profile) {
                                        attron(COLOR_PAIR(2) | A_BOLD);
                                        mvprintw(prof_row, prof_col, " -> ");
                                        attroff(COLOR_PAIR(2) | A_BOLD);
                                    } else {
                                        mvprintw(prof_row, prof_col, "    ");
                                    }
                                    mvprintw(prof_row++, prof_col + 4, "%zu. %s", i + 1, profile->name);
                                    attron(COLOR_PAIR(5));
                                    mvprintw(prof_row++, prof_col + 7, "%s", profile->description);
                                    attroff(COLOR_PAIR(5));
                                }
                                refresh();

                                int ch = getch();
                                if (ch == KEY_UP || ch == 'k' || ch == 'K') {
                                    selected_profile = (selected_profile > 0) ? selected_profile - 1 : (int)NUM_PROFILES - 1;
                                } else if (ch == KEY_DOWN || ch == 'j' || ch == 'J') {
                                    selected_profile = (selected_profile < (int)NUM_PROFILES - 1) ? selected_profile + 1 : 0;
                                } else if (ch == '\n' || ch == '\r' || ch == ' ') {
                                    const badchar_profile_t *profile = &BADCHAR_PROFILES[selected_profile];
                                    bad_char_config_t *new_config = profile_to_config(profile);
                                    if (new_config) {
                                        if (config->bad_chars) free(config->bad_chars);
                                        config->bad_chars = new_config;
                                        clear_right_panel();
                                        draw_right_panel_header("Profile Loaded");
                                        attron(COLOR_PAIR(4));
                                        mvprintw(5, RIGHT_PANEL_START + 2, "Loaded: %s", profile->name);
                                        attroff(COLOR_PAIR(4));
                                        mvprintw(6, RIGHT_PANEL_START + 2, "%zu bad characters", profile->bad_char_count);
                                        mvprintw(8, RIGHT_PANEL_START + 2, "Press any key...");
                                        refresh();
                                        getch();
                                        done = 1;
                                    }
                                } else if (ch == 27 || ch == 'q' || ch == 'Q') {
                                    done = 1;
                                }
                            }
                        } else if (sub_selection == 2) {
                            // Add bad character
                            char input[32] = "";
                            int input_row = LINES - 3;

                            clear_right_panel();
                            draw_right_panel_header("Add Bad Character");
                            mvprintw(input_row, RIGHT_PANEL_START + 2, "Enter hex value (e.g., 0x0A or 0A): ");
                            echo();
                            curs_set(1);
                            getnstr(input, sizeof(input) - 1);
                            curs_set(0);
                            noecho();

                            if (strlen(input) > 0) {
                                unsigned int byte_val;
                                if (sscanf(input, "0x%x", &byte_val) == 1 || sscanf(input, "%x", &byte_val) == 1) {
                                    if (byte_val <= 0xFF) {
                                        if (!config->bad_chars->bad_chars[byte_val]) {
                                            config->bad_chars->bad_chars[byte_val] = 1;
                                            config->bad_chars->bad_char_list[config->bad_chars->bad_char_count++] = (uint8_t)byte_val;
                                        }
                                    }
                                }
                            }
                        } else if (sub_selection == 3) {
                            // Remove bad character
                            char input[32] = "";
                            int input_row = LINES - 3;

                            clear_right_panel();
                            draw_right_panel_header("Remove Bad Character");
                            mvprintw(input_row, RIGHT_PANEL_START + 2, "Enter hex value (e.g., 0x0A or 0A): ");
                            echo();
                            curs_set(1);
                            getnstr(input, sizeof(input) - 1);
                            curs_set(0);
                            noecho();

                            if (strlen(input) > 0) {
                                unsigned int byte_val;
                                if (sscanf(input, "0x%x", &byte_val) == 1 || sscanf(input, "%x", &byte_val) == 1) {
                                    if (byte_val <= 0xFF && config->bad_chars->bad_chars[byte_val]) {
                                        config->bad_chars->bad_chars[byte_val] = 0;
                                        // Rebuild bad_char_list
                                        config->bad_chars->bad_char_count = 0;
                                        for (int i = 0; i < 256; i++) {
                                            if (config->bad_chars->bad_chars[i]) {
                                                config->bad_chars->bad_char_list[config->bad_chars->bad_char_count++] = (uint8_t)i;
                                            }
                                        }
                                    }
                                }
                            }
                        } else if (sub_selection == 4) {
                            // Clear all bad characters
                            memset(config->bad_chars->bad_chars, 0, 256);
                            config->bad_chars->bad_char_count = 0;
                        } else if (sub_selection == 5) {
                            // Reset to default (0x00 only)
                            memset(config->bad_chars->bad_chars, 0, 256);
                            config->bad_chars->bad_chars[0] = 1;
                            config->bad_chars->bad_char_count = 1;
                            config->bad_chars->bad_char_list[0] = 0x00;
                        }
                    }
                } else if (active_screen == ML_METRICS_SCREEN) {
                    if (sub_selection >= 1 && sub_selection <= 4) {
                        switch (sub_selection) {
                            case 1: config->use_ml_strategist = !config->use_ml_strategist; break;
                            case 2: config->metrics_enabled = !config->metrics_enabled; break;
                            case 3: config->metrics_export_json = !config->metrics_export_json; break;
                            case 4: config->metrics_export_csv = !config->metrics_export_csv; break;
                        }
                    }
                } else if (active_screen == CONFIG_SCREEN) {
                    if (sub_selection >= 1 && sub_selection <= 3) {
                        if (sub_selection == 1) {
                            // Load configuration
                            char filepath[512] = "";
                            int input_row = LINES - 3;

                            clear_right_panel();
                            draw_right_panel_header("Load Configuration");
                            mvprintw(input_row, RIGHT_PANEL_START + 2, "Enter config file path: ");
                            echo();
                            curs_set(1);
                            getnstr(filepath, sizeof(filepath) - 1);
                            curs_set(0);
                            noecho();

                            if (strlen(filepath) > 0) {
                                int result = load_config_from_file(config, filepath);
                                clear_right_panel();
                                draw_right_panel_header("Load Configuration");
                                if (result == 0) {
                                    attron(COLOR_PAIR(4));
                                    mvprintw(5, RIGHT_PANEL_START + 2, "Configuration loaded successfully!");
                                    attroff(COLOR_PAIR(4));
                                    // Note: Don't free - config_file may be NULL or static
                                    config->config_file = strdup(filepath);
                                } else {
                                    attron(COLOR_PAIR(3));
                                    mvprintw(5, RIGHT_PANEL_START + 2, "Failed to load configuration");
                                    attroff(COLOR_PAIR(3));
                                }
                                mvprintw(7, RIGHT_PANEL_START + 2, "Press any key to continue...");
                                refresh();
                                getch();
                            }
                        } else if (sub_selection == 2) {
                            // Save configuration
                            char filepath[512] = "";
                            int input_row = LINES - 3;

                            clear_right_panel();
                            draw_right_panel_header("Save Configuration");
                            mvprintw(input_row, RIGHT_PANEL_START + 2, "Enter config file path: ");
                            echo();
                            curs_set(1);
                            getnstr(filepath, sizeof(filepath) - 1);
                            curs_set(0);
                            noecho();

                            if (strlen(filepath) > 0) {
                                int result = save_config_to_file(config, filepath);
                                clear_right_panel();
                                draw_right_panel_header("Save Configuration");
                                if (result == 0) {
                                    attron(COLOR_PAIR(4));
                                    mvprintw(5, RIGHT_PANEL_START + 2, "Configuration saved successfully!");
                                    attroff(COLOR_PAIR(4));
                                    // Note: Don't free - config_file may be NULL or static
                                    config->config_file = strdup(filepath);
                                } else {
                                    attron(COLOR_PAIR(3));
                                    mvprintw(5, RIGHT_PANEL_START + 2, "Failed to save configuration");
                                    attroff(COLOR_PAIR(3));
                                }
                                mvprintw(7, RIGHT_PANEL_START + 2, "Press any key to continue...");
                                refresh();
                                getch();
                            }
                        } else if (sub_selection == 3) {
                            // Reset to defaults
                            clear_right_panel();
                            draw_right_panel_header("Reset to Defaults");
                            attron(COLOR_PAIR(5) | A_BOLD);
                            mvprintw(5, RIGHT_PANEL_START + 2, "Are you sure you want to reset all settings?");
                            attroff(COLOR_PAIR(5) | A_BOLD);
                            mvprintw(7, RIGHT_PANEL_START + 2, "Press 'y' to confirm, any other key to cancel...");
                            refresh();
                            int confirm = getch();
                            if (confirm == 'y' || confirm == 'Y') {
                                reset_config_to_defaults(config);
                                clear_right_panel();
                                draw_right_panel_header("Reset to Defaults");
                                attron(COLOR_PAIR(4));
                                mvprintw(5, RIGHT_PANEL_START + 2, "Configuration reset to defaults!");
                                attroff(COLOR_PAIR(4));
                                mvprintw(7, RIGHT_PANEL_START + 2, "Press any key to continue...");
                                refresh();
                                getch();
                            }
                        }
                    }
                }
            }
        } else if (ch >= '0' && ch <= '9') {
            int choice = ch - '0';
            if (active_screen == MAIN_SCREEN || active_screen == PROCESSING_SCREEN) {
                // Main menu number shortcuts
                if (choice == 0) {
                    return EXIT_SCREEN;
                } else if (choice <= 9) {
                    main_selection = choice;
                    // Map menu numbers to screen IDs
                    switch (choice) {
                        case 1: active_screen = INPUT_SCREEN; break;
                        case 2: active_screen = BATCH_SCREEN; break;
                        case 3: active_screen = OPTIONS_SCREEN; break;
                        case 4: active_screen = BAD_CHARS_SCREEN; break;
                        case 5: active_screen = OUTPUT_FORMAT_SCREEN; break;
                        case 6: active_screen = ML_METRICS_SCREEN; break;
                        case 7: active_screen = ADVANCED_OPTIONS_SCREEN; break;
                        case 8: active_screen = CONFIG_SCREEN; break;
                        case 9: active_screen = ABOUT_SCREEN; break;
                        default: active_screen = MAIN_SCREEN; break;
                    }
                    sub_selection = 1;
                }
            } else {
                // Sub-screen number shortcuts (for applicable screens)
                if (active_screen == OUTPUT_FORMAT_SCREEN && choice >= 1 && choice <= 5) {
                    sub_selection = choice;
                }
            }
        }
    }
}

// Placeholder screen implementations for split-panel layout

// Input screen - fully interactive
int show_input_screen(byvalver_config_t *config, int *current_selection) {
    clear_right_panel();
    draw_right_panel_header("Process Single File");

    int row = 5;
    int col = RIGHT_PANEL_START + 2;

    attron(A_BOLD | COLOR_PAIR(4));
    mvprintw(row++, col, "File Configuration:");
    attroff(A_BOLD | COLOR_PAIR(4));
    row++; // empty line

    const char *options[] = {
        "Browse Input File",
        "Browse Output File",
        "Type Path Manually",
        "Start Processing"
    };
    const char *descriptions[] = {
        "Use graphical file browser to select input",
        "Use graphical file browser to select output",
        "Enter file paths manually",
        "Begin processing with current settings"
    };
    int num_options = 4;

    if (*current_selection < 1 || *current_selection > num_options) {
        *current_selection = 1;
    }

    for (int i = 0; i < num_options; i++) {
        int is_selected = (*current_selection == i + 1);

        if (is_selected) {
            attron(COLOR_PAIR(2));
            mvprintw(row, col, " -> ");
            attroff(COLOR_PAIR(2));
        } else {
            mvprintw(row, col, "    ");
        }

        mvprintw(row, col + 4, "%d. %s", i + 1, options[i]);
        row++;

        if (is_selected) {
            attron(COLOR_PAIR(5));
            mvprintw(row++, col + 4, "  %s", descriptions[i]);
            attroff(COLOR_PAIR(5));
        }
    }

    row++; // empty line
    row++; // empty line

    // Show current configuration
    attron(A_BOLD);
    mvprintw(row++, col, "Current Configuration:");
    attroff(A_BOLD);
    row++; // empty line

    mvprintw(row++, col, "Input file:");
    if (config->input_file) {
        attron(COLOR_PAIR(4));
        mvprintw(row++, col + 2, "%s", config->input_file);
        attroff(COLOR_PAIR(4));
    } else {
        attron(COLOR_PAIR(3));
        mvprintw(row++, col + 2, "(Not set)");
        attroff(COLOR_PAIR(3));
    }

    row++; // empty line
    mvprintw(row++, col, "Output file:");
    if (config->output_file) {
        attron(COLOR_PAIR(4));
        mvprintw(row++, col + 2, "%s", config->output_file);
        attroff(COLOR_PAIR(4));
    } else {
        attron(COLOR_PAIR(3));
        mvprintw(row++, col + 2, "(Not set)");
        attroff(COLOR_PAIR(3));
    }

    row++; // empty line
    mvprintw(row++, col, "Press Enter to select, ESC to go back");

    return -1;
}

// Options screen - fully interactive with toggles
int show_options_screen(byvalver_config_t *config, int *current_selection) {
    clear_right_panel();
    draw_right_panel_header("Processing Options");

    int row = 5;
    int col = RIGHT_PANEL_START + 2;

    attron(A_BOLD | COLOR_PAIR(4));
    mvprintw(row++, col, "Toggle Processing Options:");
    attroff(A_BOLD | COLOR_PAIR(4));
    row++; // empty line

    const char *options[] = {
        "Biphasic Processing",
        "PIC Generation",
        "ML Strategist",
        "Verbose Output",
        "Dry Run Mode"
    };
    const char *descriptions[] = {
        "Two-phase: obfuscation then null-elimination",
        "Generate position-independent code",
        "Use ML-enhanced strategy selection",
        "Show detailed processing information",
        "Test mode - don't write output file"
    };
    int num_options = 5;

    // Initialize selection
    if (*current_selection < 1 || *current_selection > num_options) {
        *current_selection = 1;
    }

    // Display each option
    for (int i = 0; i < num_options; i++) {
        int is_selected = (*current_selection == i + 1);
        int is_enabled = 0;

        // Get current state
        switch (i) {
            case 0: is_enabled = config->use_biphasic; break;
            case 1: is_enabled = config->use_pic_generation; break;
            case 2: is_enabled = config->use_ml_strategist; break;
            case 3: is_enabled = config->verbose; break;
            case 4: is_enabled = config->dry_run; break;
        }

        // Draw selection indicator
        if (is_selected) {
            attron(COLOR_PAIR(2));
            mvprintw(row, col, " -> ");
            attroff(COLOR_PAIR(2));
        } else {
            mvprintw(row, col, "    ");
        }

        // Draw option with toggle state
        mvprintw(row, col + 4, "%d. ", i + 1);
        if (is_enabled) {
            attron(COLOR_PAIR(4) | A_BOLD);
            mvprintw(row, col + 7, "[ON]  ");
            attroff(COLOR_PAIR(4) | A_BOLD);
        } else {
            attron(COLOR_PAIR(5));
            mvprintw(row, col + 7, "[OFF] ");
            attroff(COLOR_PAIR(5));
        }
        mvprintw(row, col + 13, "%s", options[i]);
        row++;

        // Show description for selected item
        if (is_selected) {
            attron(COLOR_PAIR(5));
            mvprintw(row++, col + 7, "%s", descriptions[i]);
            attroff(COLOR_PAIR(5));
        }
    }

    row++; // empty line
    mvprintw(row++, col, "Press Enter/Space to toggle, ESC to go back");

    return -1;
}

// Bad chars screen - fully interactive
int show_bad_chars_screen(byvalver_config_t *config, int *current_selection) {
    clear_right_panel();
    draw_right_panel_header("Bad Characters");

    int row = 5;
    int col = RIGHT_PANEL_START + 2;

    // Display current bad characters
    attron(A_BOLD | COLOR_PAIR(4));
    mvprintw(row++, col, "Current Bad Characters:");
    attroff(A_BOLD | COLOR_PAIR(4));
    row++; // empty line

    if (config->bad_chars && config->bad_chars->bad_char_count > 0) {
        // Display in rows of 8 for better readability
        int count = 0;
        char line_buf[256] = "";
        for (int i = 0; i < 256; i++) {
            if (config->bad_chars->bad_chars[i]) {
                char tmp[8];
                if (count > 0 && count % 8 == 0) {
                    mvprintw(row++, col + 2, "%s", line_buf);
                    line_buf[0] = '\0';
                }
                if (count % 8 > 0) strcat(line_buf, ", ");
                snprintf(tmp, sizeof(tmp), "0x%02X", i);
                strcat(line_buf, tmp);
                count++;
            }
        }
        if (strlen(line_buf) > 0) {
            mvprintw(row++, col + 2, "%s", line_buf);
        }
        row++; // empty line
        attron(COLOR_PAIR(5));
        mvprintw(row++, col + 2, "Total: %d bad character%s",
                 config->bad_chars->bad_char_count,
                 config->bad_chars->bad_char_count == 1 ? "" : "s");
        attroff(COLOR_PAIR(5));
    } else {
        attron(COLOR_PAIR(5));
        mvprintw(row++, col + 2, "No bad characters configured");
        attroff(COLOR_PAIR(5));
    }

    row++; // empty line
    row++; // empty line

    // Menu options
    attron(A_BOLD | COLOR_PAIR(4));
    mvprintw(row++, col, "Actions:");
    attroff(A_BOLD | COLOR_PAIR(4));
    row++; // empty line

    const char *options[] = {
        "Load Profile",
        "Add Bad Character",
        "Remove Bad Character",
        "Clear All",
        "Reset to Default (0x00)"
    };

    const char *descriptions[] = {
        "Load a pre-configured bad character profile",
        "Add a new bad character (hex value)",
        "Remove a bad character from the list",
        "Remove all bad characters",
        "Reset to only null byte (0x00)"
    };

    int num_options = 5;

    // Initialize selection if not set
    if (*current_selection < 1 || *current_selection > num_options) {
        *current_selection = 1;
    }

    // Display options
    for (int i = 0; i < num_options; i++) {
        int is_selected = (*current_selection == i + 1);

        if (is_selected) {
            attron(COLOR_PAIR(2));
            mvprintw(row, col, " -> ");
            attroff(COLOR_PAIR(2));
        } else {
            mvprintw(row, col, "    ");
        }

        mvprintw(row, col + 4, "%d. %s", i + 1, options[i]);
        row++;

        // Show description for selected item
        if (is_selected) {
            attron(COLOR_PAIR(5));
            mvprintw(row++, col + 7, "%s", descriptions[i]);
            attroff(COLOR_PAIR(5));
        }
    }

    row++; // empty line
    mvprintw(row++, col, "Press Enter to select, ESC to go back");

    return -1;
}

// Batch screen - placeholder
int show_batch_screen(byvalver_config_t *config, int *current_selection) {
    clear_right_panel();
    draw_right_panel_header("Batch Processing");

    int row = 5;
    int col = RIGHT_PANEL_START + 2;

    // Display current batch configuration
    attron(A_BOLD | COLOR_PAIR(4));
    mvprintw(row++, col, "Current Configuration:");
    attroff(A_BOLD | COLOR_PAIR(4));
    row++; // empty line

    mvprintw(row++, col, "Input Directory:");
    if (config->input_file) {
        attron(COLOR_PAIR(4));
        mvprintw(row++, col + 2, "%s", config->input_file);
        attroff(COLOR_PAIR(4));
    } else {
        attron(COLOR_PAIR(3));
        mvprintw(row++, col + 2, "(Not set)");
        attroff(COLOR_PAIR(3));
    }

    mvprintw(row++, col, "Output Directory:");
    if (config->output_file) {
        attron(COLOR_PAIR(4));
        mvprintw(row++, col + 2, "%s", config->output_file);
        attroff(COLOR_PAIR(4));
    } else {
        attron(COLOR_PAIR(3));
        mvprintw(row++, col + 2, "(Not set)");
        attroff(COLOR_PAIR(3));
    }

    mvprintw(row++, col, "File Pattern:");
    attron(COLOR_PAIR(4));
    mvprintw(row++, col + 2, "%s", config->file_pattern ? config->file_pattern : "*.bin");
    attroff(COLOR_PAIR(4));

    row++; // empty line

    // Menu options
    attron(A_BOLD | COLOR_PAIR(4));
    mvprintw(row++, col, "Actions:");
    attroff(A_BOLD | COLOR_PAIR(4));
    row++; // empty line

    const char *options[] = {
        "Browse Input Directory",
        "Browse Output Directory",
        "Type Paths Manually",
        "Set File Pattern",
        "Recursive Mode",
        "Continue on Error",
        "Preserve Dir Structure",
        "Start Batch Processing"
    };

    const char *descriptions[] = {
        "Use graphical browser to select input directory",
        "Use graphical browser to select output directory",
        "Enter directory paths manually",
        "Set file pattern (e.g., *.bin, *.sc)",
        "Process subdirectories recursively",
        "Continue processing if a file fails",
        "Preserve directory structure in output",
        "Begin batch processing with current settings"
    };

    int num_options = 8;

    // Initialize selection if not set
    if (*current_selection < 1 || *current_selection > num_options) {
        *current_selection = 1;
    }

    // Display options
    for (int i = 0; i < num_options; i++) {
        int is_selected = (*current_selection == i + 1);

        if (is_selected) {
            attron(COLOR_PAIR(2));
            mvprintw(row, col, " -> ");
            attroff(COLOR_PAIR(2));
        } else {
            mvprintw(row, col, "    ");
        }

        // For toggles (options 5-7), show current state
        if (i == 4) {  // Recursive Mode
            mvprintw(row, col + 4, "%d. ", i + 1);
            if (config->recursive) {
                attron(COLOR_PAIR(4) | A_BOLD);
                mvprintw(row, col + 7, "[ON]  ");
                attroff(COLOR_PAIR(4) | A_BOLD);
            } else {
                attron(COLOR_PAIR(5));
                mvprintw(row, col + 7, "[OFF] ");
                attroff(COLOR_PAIR(5));
            }
            mvprintw(row, col + 13, "%s", options[i]);
        } else if (i == 5) {  // Continue on Error
            mvprintw(row, col + 4, "%d. ", i + 1);
            if (config->continue_on_error) {
                attron(COLOR_PAIR(4) | A_BOLD);
                mvprintw(row, col + 7, "[ON]  ");
                attroff(COLOR_PAIR(4) | A_BOLD);
            } else {
                attron(COLOR_PAIR(5));
                mvprintw(row, col + 7, "[OFF] ");
                attroff(COLOR_PAIR(5));
            }
            mvprintw(row, col + 13, "%s", options[i]);
        } else if (i == 6) {  // Preserve Dir Structure
            mvprintw(row, col + 4, "%d. ", i + 1);
            if (config->preserve_structure) {
                attron(COLOR_PAIR(4) | A_BOLD);
                mvprintw(row, col + 7, "[ON]  ");
                attroff(COLOR_PAIR(4) | A_BOLD);
            } else {
                attron(COLOR_PAIR(5));
                mvprintw(row, col + 7, "[OFF] ");
                attroff(COLOR_PAIR(5));
            }
            mvprintw(row, col + 13, "%s", options[i]);
        } else {
            mvprintw(row, col + 4, "%d. %s", i + 1, options[i]);
        }
        row++;

        // Show description for selected item
        if (is_selected) {
            attron(COLOR_PAIR(5));
            mvprintw(row++, col + 7, "%s", descriptions[i]);
            attroff(COLOR_PAIR(5));
        }
    }

    row++; // empty line
    mvprintw(row++, col, "Press Enter/Space, ESC to go back");

    return -1;
}

// Output format screen - fully interactive
int show_output_format_screen(byvalver_config_t *config, int *current_selection) {
    clear_right_panel();
    draw_right_panel_header("Output Format");

    int row = 5;
    int col = RIGHT_PANEL_START + 2;

    attron(A_BOLD | COLOR_PAIR(4));
    mvprintw(row++, col, "Select Output Format:");
    attroff(A_BOLD | COLOR_PAIR(4));
    row++; // empty line

    const char *formats[] = {"raw", "c", "python", "powershell", "hexstring"};
    const char *descriptions[] = {
        "Raw binary output",
        "C array format (unsigned char[])",
        "Python bytes format (b\"\\x..\")",
        "PowerShell byte array ([Byte[]])",
        "Hex string format (\\x01\\x02...)"
    };
    int num_formats = 5;

    // Initialize selection if not set
    if (*current_selection < 1 || *current_selection > num_formats) {
        *current_selection = 1;
    }

    // Display formats with current selection highlighted
    for (int i = 0; i < num_formats; i++) {
        int is_current = (config->output_format && strcmp(config->output_format, formats[i]) == 0);
        int is_selected = (*current_selection == i + 1);

        if (is_selected) {
            attron(COLOR_PAIR(2));
            mvprintw(row, col, " -> ");
            attroff(COLOR_PAIR(2));
        } else {
            mvprintw(row, col, "    ");
        }

        if (is_current) {
            attron(COLOR_PAIR(4) | A_BOLD);
        }
        mvprintw(row, col + 4, "%d. %s", i + 1, formats[i]);
        if (is_current) {
            mvprintw(row, col + 20, " (active)");
            attroff(COLOR_PAIR(4) | A_BOLD);
        }
        row++;

        // Show description for selected item
        if (is_selected) {
            attron(COLOR_PAIR(5));
            mvprintw(row++, col + 4, "  %s", descriptions[i]);
            attroff(COLOR_PAIR(5));
        }
    }

    row++; // empty line
    mvprintw(row++, col, "Press Enter to select, ESC to cancel");

    return -1;
}

// ML Metrics screen - fully interactive
int show_ml_metrics_screen(byvalver_config_t *config, int *current_selection) {
    clear_right_panel();
    draw_right_panel_header("ML Metrics");

    int row = 5;
    int col = RIGHT_PANEL_START + 2;

    attron(A_BOLD | COLOR_PAIR(4));
    mvprintw(row++, col, "ML & Metrics Configuration:");
    attroff(A_BOLD | COLOR_PAIR(4));
    row++; // empty line

    const char *options[] = {
        "ML Strategist",
        "Metrics Collection",
        "Export JSON",
        "Export CSV"
    };
    const char *descriptions[] = {
        "Use machine learning for strategy selection",
        "Collect strategy performance metrics",
        "Export metrics to JSON format",
        "Export metrics to CSV format"
    };
    int num_options = 4;

    if (*current_selection < 1 || *current_selection > num_options) {
        *current_selection = 1;
    }

    for (int i = 0; i < num_options; i++) {
        int is_selected = (*current_selection == i + 1);
        int is_enabled = 0;

        switch (i) {
            case 0: is_enabled = config->use_ml_strategist; break;
            case 1: is_enabled = config->metrics_enabled; break;
            case 2: is_enabled = config->metrics_export_json; break;
            case 3: is_enabled = config->metrics_export_csv; break;
        }

        if (is_selected) {
            attron(COLOR_PAIR(2));
            mvprintw(row, col, " -> ");
            attroff(COLOR_PAIR(2));
        } else {
            mvprintw(row, col, "    ");
        }

        mvprintw(row, col + 4, "%d. ", i + 1);
        if (is_enabled) {
            attron(COLOR_PAIR(4) | A_BOLD);
            mvprintw(row, col + 7, "[ON]  ");
            attroff(COLOR_PAIR(4) | A_BOLD);
        } else {
            attron(COLOR_PAIR(5));
            mvprintw(row, col + 7, "[OFF] ");
            attroff(COLOR_PAIR(5));
        }
        mvprintw(row, col + 13, "%s", options[i]);
        row++;

        if (is_selected) {
            attron(COLOR_PAIR(5));
            mvprintw(row++, col + 7, "%s", descriptions[i]);
            attroff(COLOR_PAIR(5));
        }
    }

    row++; // empty line
    mvprintw(row++, col, "Press Enter/Space to toggle, ESC to go back");

    return -1;
}

// Advanced options screen - fully interactive
int show_advanced_options_screen(byvalver_config_t *config, int *current_selection) {
    clear_right_panel();
    draw_right_panel_header("Advanced Options");

    int row = 5;
    int col = RIGHT_PANEL_START + 2;

    attron(A_BOLD | COLOR_PAIR(4));
    mvprintw(row++, col, "Advanced Settings:");
    attroff(A_BOLD | COLOR_PAIR(4));
    row++; // empty line

    const char *options[] = {
        "XOR Encoding",
        "Show Statistics",
        "Validate Output"
    };
    const char *descriptions[] = {
        "Apply XOR encoding to output shellcode",
        "Display detailed processing statistics",
        "Verify output shellcode functionality"
    };
    int num_options = 3;

    if (*current_selection < 1 || *current_selection > num_options) {
        *current_selection = 1;
    }

    for (int i = 0; i < num_options; i++) {
        int is_selected = (*current_selection == i + 1);
        int is_enabled = 0;

        switch (i) {
            case 0: is_enabled = config->encode_shellcode; break;
            case 1: is_enabled = config->show_stats; break;
            case 2: is_enabled = config->validate_output; break;
        }

        if (is_selected) {
            attron(COLOR_PAIR(2));
            mvprintw(row, col, " -> ");
            attroff(COLOR_PAIR(2));
        } else {
            mvprintw(row, col, "    ");
        }

        mvprintw(row, col + 4, "%d. ", i + 1);
        if (is_enabled) {
            attron(COLOR_PAIR(4) | A_BOLD);
            mvprintw(row, col + 7, "[ON]  ");
            attroff(COLOR_PAIR(4) | A_BOLD);
        } else {
            attron(COLOR_PAIR(5));
            mvprintw(row, col + 7, "[OFF] ");
            attroff(COLOR_PAIR(5));
        }
        mvprintw(row, col + 13, "%s", options[i]);
        row++;

        if (is_selected) {
            attron(COLOR_PAIR(5));
            mvprintw(row++, col + 7, "%s", descriptions[i]);
            attroff(COLOR_PAIR(5));
        }
    }

    row++; // empty line
    row++; // empty line

    // Show read-only settings
    attron(COLOR_PAIR(5));
    mvprintw(row++, col, "Other Settings:");
    attroff(COLOR_PAIR(5));
    mvprintw(row++, col, "  Strategy Limit: %d", config->strategy_limit);
    mvprintw(row++, col, "  Timeout:        %ds", config->timeout_seconds);
    row++; // empty line

    mvprintw(row++, col, "Press Enter/Space to toggle, ESC to go back");

    return -1;
}

// Config screen - placeholder
int show_config_screen(byvalver_config_t *config, int *current_selection) {
    clear_right_panel();
    draw_right_panel_header("Configuration");

    int row = 5;
    int col = RIGHT_PANEL_START + 2;

    attron(A_BOLD | COLOR_PAIR(4));
    mvprintw(row++, col, "Configuration Management:");
    attroff(A_BOLD | COLOR_PAIR(4));
    row++; // empty line

    const char *options[] = {
        "Load Configuration",
        "Save Configuration",
        "Reset to Defaults"
    };

    const char *descriptions[] = {
        "Load settings from a file",
        "Save current settings to a file",
        "Reset all settings to default values"
    };

    int num_options = 3;

    // Initialize selection if not set
    if (*current_selection < 1 || *current_selection > num_options) {
        *current_selection = 1;
    }

    // Display options
    for (int i = 0; i < num_options; i++) {
        int is_selected = (*current_selection == i + 1);

        if (is_selected) {
            attron(COLOR_PAIR(2));
            mvprintw(row, col, " -> ");
            attroff(COLOR_PAIR(2));
        } else {
            mvprintw(row, col, "    ");
        }

        mvprintw(row, col + 4, "%d. %s", i + 1, options[i]);
        row++;

        // Show description for selected item
        if (is_selected) {
            attron(COLOR_PAIR(5));
            mvprintw(row++, col + 7, "%s", descriptions[i]);
            attroff(COLOR_PAIR(5));
        }
    }

    row++; // empty line
    row++; // empty line

    // Show current config file if set
    if (config->config_file) {
        attron(COLOR_PAIR(5));
        mvprintw(row++, col, "Current config file:");
        attroff(COLOR_PAIR(5));
        attron(COLOR_PAIR(4));
        mvprintw(row++, col + 2, "%s", config->config_file);
        attroff(COLOR_PAIR(4));
    } else {
        attron(COLOR_PAIR(5));
        mvprintw(row++, col, "No config file loaded");
        attroff(COLOR_PAIR(5));
    }

    row++; // empty line
    mvprintw(row++, col, "Press Enter to select, ESC to go back");

    return -1;
}

// Results screen - placeholder
int show_results_screen(byvalver_config_t *config, int *current_selection) {
    (void)current_selection;  // Unused in placeholder

    clear_right_panel();
    draw_right_panel_header("Processing Results");

    int row = 5;
    int col = RIGHT_PANEL_START + 2;
    
    attron(A_BOLD | COLOR_PAIR(4));
    mvprintw(row++, col, "Last Processing Results:");
    attroff(A_BOLD | COLOR_PAIR(4));
    row++; // empty line
    mvprintw(row++, col, "Input:  %s", config->input_file ? config->input_file : "N/A");
    mvprintw(row++, col, "Output: %s", config->output_file ? config->output_file : "N/A");
    row++; // empty line
    mvprintw(row++, col, "[Detailed results after processing]");
    
    return -1;
}
int show_processing_screen(byvalver_config_t *config) {
    clear_screen();

    // Check if this is batch mode or single file mode
    int is_batch = config->batch_mode;

    if (is_batch) {
        draw_header("Batch Processing");
    } else {
        draw_header("Processing Shellcode");
    }

    int row = 5;
    if (is_batch) {
        mvprintw(row++, 5, "Batch processing directory with current configuration...");
        mvprintw(row++, 5, " ");
        mvprintw(row++, 5, "Input directory:  %s", config->input_file ? config->input_file : "Not set");
        mvprintw(row++, 5, "Output directory: %s", config->output_file ? config->output_file : "Not set");
        mvprintw(row++, 5, "File pattern:     %s", config->file_pattern ? config->file_pattern : "*.bin");
        mvprintw(row++, 5, "Recursive:        %s", config->recursive ? "Yes" : "No");
    } else {
        mvprintw(row++, 5, "Processing shellcode with current configuration...");
        mvprintw(row++, 5, " ");
        mvprintw(row++, 5, "Input file:  %s", config->input_file ? config->input_file : "Not set");
        mvprintw(row++, 5, "Output file: %s", config->output_file ? config->output_file : "Not set");
    }
    mvprintw(row++, 5, " ");

    // Check if input is set
    if (!config->input_file) {
        mvprintw(row++, 5, "Error: No input specified!");
        mvprintw(row++, 5, "Press any key to return to main menu...");
        getch();
        return MAIN_SCREEN;
    }

    if (is_batch) {
        // BATCH PROCESSING WITH LIVE UPDATES
        mvprintw(row++, 5, " ");
        int scan_row = row;
        mvprintw(row++, 5, "Scanning directory...");
        refresh();

        // Find all files matching the pattern
        file_list_t file_list;
        file_list_init(&file_list);

        if (find_files(config->input_file, config->file_pattern, config->recursive, &file_list) != 0) {
            mvprintw(row++, 5, "Error: Failed to scan directory");
            mvprintw(row++, 5, "Press any key to continue...");
            getch();
            file_list_free(&file_list);
            return MAIN_SCREEN;
        }

        // Update with file count
        mvprintw(scan_row, 5, "Scanning directory... Found %zu files", file_list.count);
        refresh();
        napms(500); // Brief pause so user can see the count

        if (file_list.count == 0) {
            mvprintw(row++, 5, "No files found matching pattern '%s'", config->file_pattern);
            mvprintw(row++, 5, "Press any key to continue...");
            getch();
            file_list_free(&file_list);
            return MAIN_SCREEN;
        }

        mvprintw(row++, 5, " ");
        mvprintw(row++, 5, "Initializing strategies...");
        refresh();

        // Initialize strategy registries (needed for processing)
        init_strategies(config->use_ml_strategist);
        if (config->use_biphasic) {
            init_obfuscation_strategies();
        }

        mvprintw(row++, 5, "Initializing bad character context...");
        refresh();

        // Initialize bad character context for processing
        init_bad_char_context(config->bad_chars);

        mvprintw(row++, 5, "Setting up batch statistics...");
        refresh();

        // Initialize batch statistics
        batch_stats_t stats;
        batch_stats_init(&stats);
        stats.total_files = file_list.count;

        // Set bad character configuration in stats
        bad_char_config_t* bad_char_config = get_bad_char_config();
        if (bad_char_config) {
            stats.bad_char_count = bad_char_config->bad_char_count;
            for (int i = 0; i < 256; i++) {
                stats.bad_char_set[i] = bad_char_config->bad_chars[i];
            }
        }

        // Set batch stats context for strategy tracking
        set_batch_stats_context(&stats);

        mvprintw(row++, 5, "Starting batch processing...");
        refresh();
        napms(1000); // Give user time to see the message

        // Save original verbose setting and suppress output during TUI processing
        int original_verbose = config->verbose;
        int original_quiet = config->quiet;
        config->verbose = 0;
        config->quiet = 1;

        // Process each file with live updates
        for (size_t i = 0; i < file_list.count; i++) {
            const char *input_path = file_list.paths[i];

            // Construct output path
            char *output_path = construct_output_path(input_path, config->input_file,
                                                     config->output_file, config->preserve_structure);
            if (!output_path) {
                stats.skipped_files++;
                continue;
            }

            // Clear screen and redraw progress
            clear_screen();
            draw_header("Batch Processing - Live Progress");

            // Dual-panel layout
            const int left_col = 2;
            const int separator_col = 60;
            const int right_col = 62;
            int left_row = 3;
            int right_row = 3;

            // Draw vertical separator
            for (int y = 3; y < LINES - 2; y++) {
                mvprintw(y, separator_col, "|");
            }

            // LEFT PANEL - Progress, Configuration, Statistics, Current File

            // Progress bar
            int bar_width = 48;
            int filled = (int)((float)(i + 1) / file_list.count * bar_width);
            mvprintw(left_row++, left_col, "Progress: [");
            attron(COLOR_PAIR(4)); // Green
            for (int j = 0; j < filled; j++) printw("=");
            attroff(COLOR_PAIR(4));
            for (int j = filled; j < bar_width; j++) printw(" ");
            printw("] %zu/%zu", i + 1, file_list.count);
            left_row++;

            // Configuration display
            mvprintw(left_row++, left_col, " ");
            mvprintw(left_row++, left_col, "Configuration:");

            // Bad characters
            if (config->bad_chars && config->bad_chars->bad_char_count > 0) {
                attron(COLOR_PAIR(5));
                // Build hex string of bad chars from bad_char_list (not bitmap)
                char bad_chars_str[256];
                int pos = 0;
                for (int bc = 0; bc < config->bad_chars->bad_char_count && pos < 250; bc++) {
                    if (bc > 0) {
                        pos += snprintf(bad_chars_str + pos, sizeof(bad_chars_str) - pos, ",");
                    }
                    pos += snprintf(bad_chars_str + pos, sizeof(bad_chars_str) - pos,
                                   "%02x", config->bad_chars->bad_char_list[bc]);
                }
                // Show actual chars if <= 25 chars, otherwise show count
                if (strlen(bad_chars_str) <= 25) {
                    mvprintw(left_row++, left_col, "  Bad chars: %s", bad_chars_str);
                } else {
                    mvprintw(left_row++, left_col, "  Bad chars: %d configured", config->bad_chars->bad_char_count);
                }
                attroff(COLOR_PAIR(5));
            } else {
                attron(COLOR_PAIR(5));
                mvprintw(left_row++, left_col, "  Bad chars: 00");
                attroff(COLOR_PAIR(5));
            }

            // Processing options
            if (config->use_biphasic) {
                attron(COLOR_PAIR(4));
                mvprintw(left_row++, left_col, "  Biphasic: ON");
                attroff(COLOR_PAIR(4));
            }
            if (config->use_pic_generation) {
                attron(COLOR_PAIR(4));
                mvprintw(left_row++, left_col, "  PIC Generation: ON");
                attroff(COLOR_PAIR(4));
            }
            if (config->encode_shellcode) {
                attron(COLOR_PAIR(4));
                mvprintw(left_row++, left_col, "  XOR Encoding: ON (key: 0x%08X)", config->xor_key);
                attroff(COLOR_PAIR(4));
            }
            if (config->use_ml_strategist) {
                attron(COLOR_PAIR(4));
                mvprintw(left_row++, left_col, "  ML Strategist: ON");
                attroff(COLOR_PAIR(4));
            }

            // Output format
            attron(COLOR_PAIR(5));
            mvprintw(left_row++, left_col, "  Output format: %s",
                    config->output_format ? config->output_format : "raw");
            attroff(COLOR_PAIR(5));

            // Statistics
            mvprintw(left_row++, left_col, " ");
            mvprintw(left_row++, left_col, "File Statistics:");

            size_t total_attempted = stats.processed_files + stats.failed_files + stats.skipped_files;
            mvprintw(left_row++, left_col, "  Completed:  %zu / %zu", total_attempted, file_list.count);

            attron(COLOR_PAIR(4));
            mvprintw(left_row++, left_col, "  Successful: %zu", stats.processed_files);
            attroff(COLOR_PAIR(4));

            attron(COLOR_PAIR(3));
            mvprintw(left_row++, left_col, "  Failed:     %zu", stats.failed_files);
            attroff(COLOR_PAIR(3));

            if (stats.skipped_files > 0) {
                attron(COLOR_PAIR(5));
                mvprintw(left_row++, left_col, "  Skipped:    %zu", stats.skipped_files);
                attroff(COLOR_PAIR(5));
            }

            // Show success rate if any files attempted
            if (total_attempted > 0) {
                float success_rate = (float)stats.processed_files / total_attempted * 100.0f;
                if (success_rate >= 80.0f) attron(COLOR_PAIR(4));
                else if (success_rate >= 50.0f) attron(COLOR_PAIR(5));
                else attron(COLOR_PAIR(3));
                mvprintw(left_row++, left_col, "  Success rate: %.1f%%", success_rate);
                attroff(COLOR_PAIR(4));
                attroff(COLOR_PAIR(5));
                attroff(COLOR_PAIR(3));
            }

            left_row++;

            // Current file
            mvprintw(left_row++, left_col, "Current file:");
            attron(A_BOLD);
            // Replace home directory with ~ for readability
            const char *home = getenv("HOME");
            const char *display_path = input_path;
            char tilde_path[512];
            if (home && strncmp(input_path, home, strlen(home)) == 0) {
                snprintf(tilde_path, sizeof(tilde_path), "~%s", input_path + strlen(home));
                display_path = tilde_path;
            }
            // Truncate filename to fit in left panel (54 chars with 2-space indent)
            size_t input_len = strlen(display_path);
            if (input_len > 54) {
                // Show end of path with ellipsis
                mvprintw(left_row++, left_col, "  ...%s", display_path + input_len - 51);
            } else {
                mvprintw(left_row++, left_col, "  %s", display_path);
            }
            attroff(A_BOLD);
            left_row++;

            // Next file preview
            if (i + 1 < file_list.count) {
                mvprintw(left_row++, left_col, "Next file:");
                attron(COLOR_PAIR(5)); // Yellow/dim
                // Replace home directory with ~ for readability
                const char *display_next = file_list.paths[i + 1];
                char tilde_next[512];
                if (home && strncmp(file_list.paths[i + 1], home, strlen(home)) == 0) {
                    snprintf(tilde_next, sizeof(tilde_next), "~%s", file_list.paths[i + 1] + strlen(home));
                    display_next = tilde_next;
                }
                size_t next_len = strlen(display_next);
                if (next_len > 54) {
                    // Show end of path with ellipsis
                    mvprintw(left_row++, left_col, "  ...%s", display_next + next_len - 51);
                } else {
                    mvprintw(left_row++, left_col, "  %s", display_next);
                }
                attroff(COLOR_PAIR(5));
            }

            // RIGHT PANEL - Strategy Statistics Table

            // Add spacing to align with progress bar
            right_row += 2;

            // Strategy statistics table
            if (stats.strategy_count > 0) {
                mvprintw(right_row++, right_col, "Strategy Usage Statistics:");
                mvprintw(right_row++, right_col, "%-38s %6s %6s %7s",
                        "Strategy", "Total", "Succ", "Rate");
                mvprintw(right_row++, right_col, "%s",
                        "----------------------------------------------------------------");

                // Show ALL strategies that fit on screen
                int max_strategies = LINES - right_row - 3; // Leave space for footer
                int strategies_to_show = (int)stats.strategy_count < max_strategies ?
                                        (int)stats.strategy_count : max_strategies;

                for (int s = 0; s < strategies_to_show; s++) {
                    strategy_stats_t *usage = &stats.strategy_stats[s];
                    int total_uses = usage->success_count + usage->failure_count;
                    float success_rate = total_uses > 0 ?
                        (float)usage->success_count / total_uses * 100.0f : 0.0f;

                    if (success_rate >= 80.0f) {
                        attron(COLOR_PAIR(4)); // Green for high success
                    } else if (success_rate >= 50.0f) {
                        attron(COLOR_PAIR(5)); // Yellow for medium
                    } else {
                        attron(COLOR_PAIR(3)); // Red for low success
                    }

                    // Truncate strategy name to 38 chars for right panel
                    char truncated_name[64];
                    snprintf(truncated_name, sizeof(truncated_name), "%s", usage->name);

                    mvprintw(right_row++, right_col, "%-38s %6d %6d %6.1f%%",
                            truncated_name, total_uses, usage->success_count, success_rate);

                    attroff(COLOR_PAIR(4));
                    attroff(COLOR_PAIR(5));
                    attroff(COLOR_PAIR(3));
                }

                // Show indicator if more strategies exist
                if ((int)stats.strategy_count > strategies_to_show) {
                    attron(COLOR_PAIR(5));
                    mvprintw(right_row++, right_col, "... and %d more strategies",
                            (int)stats.strategy_count - strategies_to_show);
                    attroff(COLOR_PAIR(5));
                }

                // Clear remaining lines in right panel to avoid garbage
                for (int y = right_row; y < LINES - 2; y++) {
                    mvprintw(y, right_col, "%*s", COLS - right_col - 1, "");
                }
            }

            refresh();

            // Redirect stdout/stderr for this file's processing only
            int stdout_backup = dup(STDOUT_FILENO);
            int stderr_backup = dup(STDERR_FILENO);
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }

            // Process the file
            size_t input_size = 0, output_size = 0;
            int result = process_single_file(input_path, output_path, config, &input_size, &output_size);

            // Restore stdout/stderr immediately after processing
            fflush(stdout);
            fflush(stderr);
            dup2(stdout_backup, STDOUT_FILENO);
            dup2(stderr_backup, STDERR_FILENO);
            close(stdout_backup);
            close(stderr_backup);

            if (result == EXIT_SUCCESS) {
                stats.processed_files++;
                stats.total_input_bytes += input_size;
                stats.total_output_bytes += output_size;

                // Count file complexity statistics
                FILE *input_file = fopen(input_path, "rb");
                if (input_file) {
                    uint8_t *input_data = malloc(input_size);
                    if (input_data && fread(input_data, 1, input_size, input_file) == input_size) {
                        int instr_count, bad_char_count;
                        count_shellcode_stats(input_data, input_size, &instr_count, &bad_char_count);
                        batch_stats_add_file_stats(&stats, input_path, input_size,
                                                 output_size, instr_count, bad_char_count, 1);
                    }
                    if (input_data) free(input_data);
                    fclose(input_file);
                }
            } else {
                stats.failed_files++;
                batch_stats_add_failed_file(&stats, input_path);

                // Add file stats for failed files too
                FILE *input_file = fopen(input_path, "rb");
                if (input_file) {
                    fseek(input_file, 0, SEEK_END);
                    size_t fsize = ftell(input_file);
                    fseek(input_file, 0, SEEK_SET);

                    if (fsize > 0) {
                        uint8_t *input_data = malloc(fsize);
                        if (input_data && fread(input_data, 1, fsize, input_file) == fsize) {
                            int instr_count, bad_char_count;
                            count_shellcode_stats(input_data, input_size, &instr_count, &bad_char_count);
                            batch_stats_add_file_stats(&stats, input_path, fsize,
                                                     0, instr_count, bad_char_count, 0);
                        }
                        if (input_data) free(input_data);
                    }
                    fclose(input_file);
                }
            }

            free(output_path);

            // Small delay so user can see progress
            napms(50);
        }

        // Final summary screen
        clear_screen();
        draw_header("Batch Processing Complete");

        int summary_row = 5;
        mvprintw(summary_row++, 5, "Batch processing completed!");
        mvprintw(summary_row++, 5, " ");

        // Final statistics
        attron(A_BOLD);
        mvprintw(summary_row++, 5, "Final Statistics:");
        attroff(A_BOLD);
        mvprintw(summary_row++, 5, " ");
        mvprintw(summary_row++, 5, "  Total files:      %zu", stats.total_files);
        attron(COLOR_PAIR(4));
        mvprintw(summary_row++, 5, "  Successful:       %zu", stats.processed_files);
        attroff(COLOR_PAIR(4));
        attron(COLOR_PAIR(3));
        mvprintw(summary_row++, 5, "  Failed:           %zu", stats.failed_files);
        attroff(COLOR_PAIR(3));
        mvprintw(summary_row++, 5, "  Skipped:          %zu", stats.skipped_files);
        mvprintw(summary_row++, 5, " ");
        mvprintw(summary_row++, 5, "  Total input:      %zu bytes", stats.total_input_bytes);
        mvprintw(summary_row++, 5, "  Total output:     %zu bytes", stats.total_output_bytes);

        if (stats.total_input_bytes > 0) {
            double avg_ratio = (double)stats.total_output_bytes / (double)stats.total_input_bytes;
            mvprintw(summary_row++, 5, "  Average ratio:    %.2fx", avg_ratio);
        }

        mvprintw(summary_row++, 5, " ");
        mvprintw(summary_row++, 5, "Press any key to return to main menu...");
        refresh();

        getch();

        // Restore original verbose/quiet settings
        config->verbose = original_verbose;
        config->quiet = original_quiet;

        // Cleanup
        file_list_free(&file_list);
        batch_stats_free(&stats);

        return MAIN_SCREEN;
    } else {
        // Single file processing
        int row = 5;
        mvprintw(row++, 5, "Initializing strategies...");
        refresh();

        // Initialize strategy registries (needed for processing)
        init_strategies(config->use_ml_strategist);
        if (config->use_biphasic) {
            init_obfuscation_strategies();
        }

        // Initialize bad character context for processing
        init_bad_char_context(config->bad_chars);

        mvprintw(row++, 5, "Processing file...");
        refresh();

        // Save original verbose setting and suppress output during TUI processing
        int original_verbose = config->verbose;
        int original_quiet = config->quiet;
        config->verbose = 0;
        config->quiet = 1;

        // Redirect stdout/stderr to suppress console output during processing
        int stdout_backup = dup(STDOUT_FILENO);
        int stderr_backup = dup(STDERR_FILENO);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        size_t input_size = 0;
        size_t output_size = 0;
        int result = process_single_file(config->input_file, config->output_file,
                                          config, &input_size, &output_size);

        // Restore stdout/stderr immediately after processing
        fflush(stdout);
        fflush(stderr);
        dup2(stdout_backup, STDOUT_FILENO);
        dup2(stderr_backup, STDERR_FILENO);
        close(stdout_backup);
        close(stderr_backup);

        // Restore original verbose/quiet settings
        config->verbose = original_verbose;
        config->quiet = original_quiet;

        // Store results globally for the results screen
        g_last_input_size = input_size;
        g_last_output_size = output_size;
        g_last_processing_result = result;

        // Clear and redraw screen after stdout/stderr restoration
        clear_screen();
        draw_header("Processing Shellcode");
        row = 5;
        mvprintw(row++, 5, "Processing shellcode with current configuration...");
        mvprintw(row++, 5, " ");
        mvprintw(row++, 5, "Input file:  %s", config->input_file ? config->input_file : "Not set");
        mvprintw(row++, 5, "Output file: %s", config->output_file ? config->output_file : "Not set");
        mvprintw(row++, 5, " ");

        // Configuration display
        mvprintw(row++, 5, "Configuration:");

        // Bad characters
        if (config->bad_chars && config->bad_chars->bad_char_count > 0) {
            attron(COLOR_PAIR(5));
            mvprintw(row++, 5, "  Bad chars: %d configured", config->bad_chars->bad_char_count);
            attroff(COLOR_PAIR(5));
        } else {
            attron(COLOR_PAIR(5));
            mvprintw(row++, 5, "  Bad chars: Default (0x00)");
            attroff(COLOR_PAIR(5));
        }

        // Processing options
        if (config->use_biphasic) {
            attron(COLOR_PAIR(4));
            mvprintw(row++, 5, "  Biphasic: ON");
            attroff(COLOR_PAIR(4));
        }
        if (config->use_pic_generation) {
            attron(COLOR_PAIR(4));
            mvprintw(row++, 5, "  PIC Generation: ON");
            attroff(COLOR_PAIR(4));
        }
        if (config->encode_shellcode) {
            attron(COLOR_PAIR(4));
            mvprintw(row++, 5, "  XOR Encoding: ON (key: 0x%08X)", config->xor_key);
            attroff(COLOR_PAIR(4));
        }
        if (config->use_ml_strategist) {
            attron(COLOR_PAIR(4));
            mvprintw(row++, 5, "  ML Strategist: ON");
            attroff(COLOR_PAIR(4));
        }

        // Output format
        attron(COLOR_PAIR(5));
        mvprintw(row++, 5, "  Output format: %s",
                config->output_format ? config->output_format : "raw");
        attroff(COLOR_PAIR(5));

        mvprintw(row++, 5, " ");

        if (result == EXIT_SUCCESS) {
            mvprintw(row++, 5, "Processing completed successfully!");
            mvprintw(row++, 5, "Input size: %zu bytes", input_size);
            mvprintw(row++, 5, "Output size: %zu bytes", output_size);
            if (input_size > 0) {
                double ratio = (double)output_size / (double)input_size;
                mvprintw(row++, 5, "Size ratio: %.2fx", ratio);
            }
        } else {
            mvprintw(row++, 5, "Processing failed with error code: %d", result);
            if (result == EXIT_INPUT_FILE_ERROR) {
                mvprintw(row++, 5, "Error: Cannot open or read input file");
            } else if (result == EXIT_PROCESSING_FAILED) {
                mvprintw(row++, 5, "Error: Shellcode processing failed");
            } else if (result == EXIT_OUTPUT_FILE_ERROR) {
                mvprintw(row++, 5, "Error: Cannot write output file");
            }
        }

        mvprintw(row++, 5, " ");
        mvprintw(row++, 5, "Press any key to continue...");
        getch();

        return (result == EXIT_SUCCESS) ? RESULTS_SCREEN : MAIN_SCREEN;
    }
}

// Results screen implementation

// About screen implementation (renders in right panel)
int show_about_screen() {
    clear_right_panel();
    draw_right_panel_header("About byvalver");

    int row = 5;
    int col = RIGHT_PANEL_START + 2;

    attron(A_BOLD | COLOR_PAIR(4));
    mvprintw(row++, col, "byvalver - Bad-Character Elimination Framework");
    attroff(A_BOLD | COLOR_PAIR(4));

    row++; // empty line
    mvprintw(row++, col, "Version: %d.%d.%d", BYVALVER_VERSION_MAJOR, BYVALVER_VERSION_MINOR, BYVALVER_VERSION_PATCH);
    row++; // empty line

    attron(A_BOLD);
    mvprintw(row++, col, "Description:");
    attroff(A_BOLD);
    mvprintw(row++, col, "Advanced C-based command-line tool for automated");
    mvprintw(row++, col, "elimination of bad characters from shellcode while");
    mvprintw(row++, col, "preserving functional equivalence.");
    row++; // empty line

    attron(A_BOLD | COLOR_PAIR(4));
    mvprintw(row++, col, "Core Features:");
    attroff(A_BOLD | COLOR_PAIR(4));
    mvprintw(row++, col, "  * Null-byte elimination");
    mvprintw(row++, col, "  * Generic bad character removal");
    mvprintw(row++, col, "  * Biphasic processing");
    mvprintw(row++, col, "    (obfuscation + elimination)");
    mvprintw(row++, col, "  * Position-independent code (PIC)");
    mvprintw(row++, col, "  * ML-enhanced strategy selection");
    mvprintw(row++, col, "  * Batch processing");
    mvprintw(row++, col, "  * Interactive TUI mode");
    row++; // empty line

    attron(A_BOLD | COLOR_PAIR(4));
    mvprintw(row++, col, "Output Formats:");
    attroff(A_BOLD | COLOR_PAIR(4));
    mvprintw(row++, col, "  * Raw binary");
    mvprintw(row++, col, "  * C array");
    mvprintw(row++, col, "  * Python bytes");
    mvprintw(row++, col, "  * PowerShell array");
    mvprintw(row++, col, "  * Hex string");

    return -1; // Continue showing
}

// Utility functions implementation
void clear_screen() {
    clear();
    refresh();
}

void draw_header(const char *title) {
    attron(COLOR_PAIR(1));
    mvprintw(0, 0, "%*s", COLS, " ");
    mvprintw(0, (COLS - strlen(title)) / 2, "%s", title);
    attroff(COLOR_PAIR(1));
}

void draw_footer() {
    attron(COLOR_PAIR(1));
    mvprintw(LINES - 1, 0, "%*s", COLS, " ");
    mvprintw(LINES - 1, 2, "Use arrow keys to navigate, Enter to select, 'q' to quit");
    attroff(COLOR_PAIR(1));
    refresh();
}

void draw_menu_item(int row, int col, const char *text, int selected) {
    if (selected) {
        attron(COLOR_PAIR(2)); // Highlight selected items
        mvprintw(row, col, " -> %s", text);
        attroff(COLOR_PAIR(2));
    } else {
        mvprintw(row, col, "    %s", text);
    }
}

// Panel drawing functions for split-panel layout
void draw_vertical_separator() {
    attron(COLOR_PAIR(1));
    for (int i = 1; i < LINES - 1; i++) {
        mvprintw(i, SEPARATOR_COL, "|");
    }
    attroff(COLOR_PAIR(1));
}

void clear_right_panel() {
    for (int i = 1; i < LINES - 1; i++) {
        mvprintw(i, RIGHT_PANEL_START, "%*s", RIGHT_PANEL_WIDTH, " ");
    }
}

void draw_right_panel_header(const char *title) {
    int title_col = RIGHT_PANEL_START + (RIGHT_PANEL_WIDTH - strlen(title)) / 2;
    if (title_col < RIGHT_PANEL_START) title_col = RIGHT_PANEL_START;

    attron(COLOR_PAIR(1) | A_BOLD);
    mvprintw(2, RIGHT_PANEL_START, "%*s", RIGHT_PANEL_WIDTH, " ");
    mvprintw(2, title_col, "%s", title);
    attroff(COLOR_PAIR(1) | A_BOLD);
}
