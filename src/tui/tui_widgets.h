#ifndef TUI_WIDGETS_H
#define TUI_WIDGETS_H

#include "../cli.h"
#include <ncurses.h>

// Input field widget
typedef struct {
    int x, y;           // Position
    int width;          // Width of the field
    char *label;        // Label text
    char *value;        // Current value
    int max_length;     // Maximum length of input
} input_field_t;

// Button widget
typedef struct {
    int x, y;           // Position
    int width, height;  // Dimensions
    char *text;         // Button text
    int is_selected;    // Whether button is selected
} button_t;

// Checkbox widget
typedef struct {
    int x, y;           // Position
    char *label;        // Label text
    int *value;         // Pointer to the value to toggle
    int is_selected;    // Whether checkbox is selected
} checkbox_t;

// List widget
typedef struct {
    int x, y;           // Position
    int width, height;  // Dimensions
    char **items;       // List of items
    int item_count;     // Number of items
    int selected_item;  // Index of selected item
} list_t;

// Function to create an input field
input_field_t* create_input_field(int x, int y, int width, const char *label, const char *initial_value);

// Function to draw an input field
void draw_input_field(input_field_t *field);

// Function to handle input for an input field
int handle_input_field(input_field_t *field);

// Function to free an input field
void free_input_field(input_field_t *field);

// Function to create a button
button_t* create_button(int x, int y, int width, int height, const char *text);

// Function to draw a button
void draw_button(button_t *btn);

// Function to handle button clicks
int handle_button(button_t *btn);

// Function to free a button
void free_button(button_t *btn);

// Function to create a checkbox
checkbox_t* create_checkbox(int x, int y, const char *label, int *value);

// Function to draw a checkbox
void draw_checkbox(checkbox_t *chk);

// Function to handle checkbox clicks
int handle_checkbox(checkbox_t *chk);

// Function to free a checkbox
void free_checkbox(checkbox_t *chk);

// Function to create a list
list_t* create_list(int x, int y, int width, int height, char **items, int item_count);

// Function to draw a list
void draw_list(list_t *lst);

// Function to handle list navigation
int handle_list(list_t *lst);

// Function to free a list
void free_list(list_t *lst);

// Utility function to clear a region
void clear_region(int x, int y, int width, int height);

#endif