APP_NAME := user_app_firewall
APP_SRC := user_app_firewall.c
APP_OBJ := $(APP_SRC:.c=.o)

all: $(APP_NAME)

$(APP_NAME): $(APP_OBJ)
	$(CC) -o $(APP_NAME) $(APP_OBJ)

%.o: %.c
	$(CC) -c $< -o $@

clean:
	rm -f $(APP_NAME) $(APP_OBJ)
