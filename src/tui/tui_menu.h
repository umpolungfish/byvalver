#ifndef TUI_MENU_H
#define TUI_MENU_H

#include "../cli.h"
#include <ncurses.h>

// Function to run the interactive TUI menu
int run_tui_menu(byvalver_config_t *config);

// Function to initialize ncurses and set up the TUI environment
int init_tui();

// Function to clean up ncurses and restore terminal settings
void cleanup_tui();

#endif