#define _GNU_SOURCE  // Required for strdup function
#include "tui_widgets.h"
#include <string.h>
#include <stdlib.h>

// Function to create an input field
input_field_t* create_input_field(int x, int y, int width, const char *label, const char *initial_value) {
    input_field_t *field = malloc(sizeof(input_field_t));
    if (!field) return NULL;
    
    field->x = x;
    field->y = y;
    field->width = width;
    field->label = strdup(label);
    field->max_length = width - 2; // Account for border
    
    // Allocate space for value
    field->value = malloc(field->max_length + 1);
    if (!field->value) {
        free(field->label);
        free(field);
        return NULL;
    }
    
    if (initial_value) {
        strncpy(field->value, initial_value, field->max_length);
        field->value[field->max_length] = '\0';
    } else {
        field->value[0] = '\0';
    }
    
    return field;
}

// Function to draw an input field
void draw_input_field(input_field_t *field) {
    if (!field) return;
    
    // Draw label
    mvprintw(field->y, field->x, "%s", field->label);
    
    // Draw input box
    mvaddch(field->y, field->x + strlen(field->label) + 1, '[');
    for (int i = 0; i < field->width - 2; i++) {
        mvaddch(field->y, field->x + strlen(field->label) + 2 + i, ' ');
    }
    mvaddch(field->y, field->x + strlen(field->label) + field->width - 1, ']');
    
    // Draw value inside the box
    mvprintw(field->y, field->x + strlen(field->label) + 2, "%-*s", field->width - 3, field->value);
}

// Function to handle input for an input field
int handle_input_field(input_field_t *field) {
    if (!field) return -1;
    
    // Move cursor to the input field
    move(field->y, field->x + strlen(field->label) + 2);
    
    // Enable echoing for input
    echo();
    
    // Get input string
    char input[field->max_length + 1];
    getnstr(input, field->max_length);
    
    // Disable echoing
    noecho();
    
    // Update the field value
    strncpy(field->value, input, field->max_length);
    field->value[field->max_length] = '\0';
    
    return 0;
}

// Function to free an input field
void free_input_field(input_field_t *field) {
    if (!field) return;
    
    if (field->label) free(field->label);
    if (field->value) free(field->value);
    free(field);
}

// Function to create a button
button_t* create_button(int x, int y, int width, int height, const char *text) {
    button_t *btn = malloc(sizeof(button_t));
    if (!btn) return NULL;
    
    btn->x = x;
    btn->y = y;
    btn->width = width;
    btn->height = height;
    btn->text = strdup(text);
    btn->is_selected = 0;
    
    return btn;
}

// Function to draw a button
void draw_button(button_t *btn) {
    if (!btn) return;
    
    int text_len = strlen(btn->text);
    int start_x = btn->x + (btn->width - text_len) / 2;
    
    // Draw button frame
    for (int y = btn->y; y < btn->y + btn->height; y++) {
        for (int x = btn->x; x < btn->x + btn->width; x++) {
            mvaddch(y, x, ' ');
        }
    }
    
    // Draw button text
    mvprintw(btn->y + btn->height / 2, start_x, "%s", btn->text);
    
    // Draw button border
    mvaddch(btn->y, btn->x, '+');
    mvaddch(btn->y, btn->x + btn->width - 1, '+');
    mvaddch(btn->y + btn->height - 1, btn->x, '+');
    mvaddch(btn->y + btn->height - 1, btn->x + btn->width - 1, '+');
    
    for (int x = btn->x + 1; x < btn->x + btn->width - 1; x++) {
        mvaddch(btn->y, x, '-');
        mvaddch(btn->y + btn->height - 1, x, '-');
    }
    
    for (int y = btn->y + 1; y < btn->y + btn->height - 1; y++) {
        mvaddch(y, btn->x, '|');
        mvaddch(y, btn->x + btn->width - 1, '|');
    }
}

// Function to handle button clicks
int handle_button(button_t *btn) {
    if (!btn) return -1;
    
    // In a real implementation, this would handle mouse clicks or keyboard navigation
    // For now, we'll just return success
    return 0;
}

// Function to free a button
void free_button(button_t *btn) {
    if (!btn) return;
    
    if (btn->text) free(btn->text);
    free(btn);
}

// Function to create a checkbox
checkbox_t* create_checkbox(int x, int y, const char *label, int *value) {
    checkbox_t *chk = malloc(sizeof(checkbox_t));
    if (!chk) return NULL;
    
    chk->x = x;
    chk->y = y;
    chk->label = strdup(label);
    chk->value = value;
    chk->is_selected = 0;
    
    return chk;
}

// Function to draw a checkbox
void draw_checkbox(checkbox_t *chk) {
    if (!chk) return;
    
    // Draw checkbox
    mvprintw(chk->y, chk->x, "[%c] %s", *(chk->value) ? 'X' : ' ', chk->label);
}

// Function to handle checkbox clicks
int handle_checkbox(checkbox_t *chk) {
    if (!chk) return -1;
    
    // Toggle the value
    *(chk->value) = !(*(chk->value));
    
    return 0;
}

// Function to free a checkbox
void free_checkbox(checkbox_t *chk) {
    if (!chk) return;
    
    if (chk->label) free(chk->label);
    free(chk);
}

// Function to create a list
list_t* create_list(int x, int y, int width, int height, char **items, int item_count) {
    list_t *lst = malloc(sizeof(list_t));
    if (!lst) return NULL;
    
    lst->x = x;
    lst->y = y;
    lst->width = width;
    lst->height = height;
    lst->item_count = item_count;
    lst->selected_item = 0;
    
    // Copy items
    lst->items = malloc(item_count * sizeof(char*));
    if (!lst->items) {
        free(lst);
        return NULL;
    }
    
    for (int i = 0; i < item_count; i++) {
        lst->items[i] = strdup(items[i]);
    }
    
    return lst;
}

// Function to draw a list
void draw_list(list_t *lst) {
    if (!lst) return;
    
    // Draw list border
    for (int y = lst->y; y < lst->y + lst->height; y++) {
        for (int x = lst->x; x < lst->x + lst->width; x++) {
            if (y == lst->y || y == lst->y + lst->height - 1) {
                mvaddch(y, x, '-');
            } else if (x == lst->x || x == lst->x + lst->width - 1) {
                mvaddch(y, x, '|');
            } else {
                mvaddch(y, x, ' ');
            }
        }
    }
    
    // Draw corner characters
    mvaddch(lst->y, lst->x, '+');
    mvaddch(lst->y, lst->x + lst->width - 1, '+');
    mvaddch(lst->y + lst->height - 1, lst->x, '+');
    mvaddch(lst->y + lst->height - 1, lst->x + lst->width - 1, '+');
    
    // Draw items
    for (int i = 0; i < lst->item_count && i < lst->height - 2; i++) {
        // int actual_index = i + (lst->y + 1);  // Removed unused variable
        if (i == lst->selected_item) {
            attron(COLOR_PAIR(2)); // Highlight selected item
        }
        mvprintw(lst->y + 1 + i, lst->x + 1, "%-*s", lst->width - 2, lst->items[i]);
        if (i == lst->selected_item) {
            attroff(COLOR_PAIR(2));
        }
    }
}

// Function to handle list navigation
int handle_list(list_t *lst) {
    if (!lst) return -1;
    
    int ch;
    while ((ch = getch()) != '\n' && ch != '\r') {
        if (ch == KEY_UP) {
            if (lst->selected_item > 0) {
                lst->selected_item--;
            }
        } else if (ch == KEY_DOWN) {
            if (lst->selected_item < lst->item_count - 1) {
                lst->selected_item++;
            }
        }
        
        // Redraw the list after navigation
        draw_list(lst);
        refresh();
    }
    
    return lst->selected_item;
}

// Function to free a list
void free_list(list_t *lst) {
    if (!lst) return;
    
    if (lst->items) {
        for (int i = 0; i < lst->item_count; i++) {
            if (lst->items[i]) {
                free(lst->items[i]);
            }
        }
        free(lst->items);
    }
    free(lst);
}

// Utility function to clear a region
void clear_region(int x, int y, int width, int height) {
    for (int row = y; row < y + height; row++) {
        for (int col = x; col < x + width; col++) {
            mvaddch(row, col, ' ');
        }
    }
}