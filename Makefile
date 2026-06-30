NAME		= woody-woodpacker
CC		= gcc
CFLAGS		= -Wall -Wextra -Werror
INCLUDES	= -I include/
SRC_DIR		= src/
OBJ_DIR		= obj/
SRCS		= $(wildcard $(SRC_DIR)*.c)
OBJS		= $(SRCS:$(SRC_DIR)%.c=$(OBJ_DIR)%.o)

GREEN		= \033[0;32m
YELLOW		= \033[0;33m
RESET		= \033[0m

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(NAME)
	@echo "$(GREEN)✓ $(NAME) compilé$(RESET)"

$(OBJ_DIR)%.o: $(SRC_DIR)%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR)
	@echo "$(YELLOW)obj/ supprimé$(RESET)"

fclean: clean
	rm -f $(NAME)
	@echo "$(YELLOW)$(NAME) supprimé$(RESET)"

re: fclean all

.PHONY: all clean fclean re
