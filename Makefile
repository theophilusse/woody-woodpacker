NAME		= woody-woodpacker
PACKED_ELF_NAME = woody

CC		= gcc
CFLAGS		= -Wall -Wextra -Werror
INCLUDES	= -I include/

SRC_DIR		= src/
OBJ_DIR		= obj/

SRCS		= $(wildcard $(SRC_DIR)*.c)
OBJS		= $(SRCS:$(SRC_DIR)%.c=$(OBJ_DIR)%.o)

# ── couleurs ────────────────────────────────────────────────────────────────
GREEN		= \033[0;32m
YELLOW		= \033[0;33m
RESET		= \033[0m

# ── règles principales ───────────────────────────────────────────────────────
all: $(NAME)

$(NAME): $(OBJS)
	echo "Executable"
	$(CC) $(CFLAGS) $(OBJS) -o $(NAME) -lpcap -lpthread -lm
	@echo "$(GREEN)✓ $(NAME) compilé$(RESET)"

$(OBJ_DIR)%.o: $(SRC_DIR)%.c
	@mkdir -p $(OBJ_DIR)
	@echo Compile $<
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# ── nettoyage ────────────────────────────────────────────────────────────────
clean:
	rm -f $(PACKED_ELF_NAME)
	@echo "$(YELLOW)woody supprimé$(RESET)"
	rm -rf $(OBJ_DIR)
	@echo "$(YELLOW)obj/ supprimé$(RESET)"

fclean: clean
	rm -f $(NAME)
	@echo "$(YELLOW)$(NAME) supprimé$(RESET)"

re: fclean all

config:
	@sudo apt update
	@sudo apt install gcc
	@sudo apt install libpcap0.8-dev

# ── phony ────────────────────────────────────────────────────────────────────
.PHONY: all clean fclean re config
