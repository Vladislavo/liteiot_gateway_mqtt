CC 		= gcc

CFLAGS 		= -Wall
LFLAGS		= -pthread -lpq -lm -lpaho-mqtt3a

INC_DIR		= ../inc
OBJ_DIR		= ../obj
BIN_DIR		= ../bin
SRC_DIR		= .

#MQTT_SRC_DIR	= ../lib/paho.mqtt.c/src
#MQTT_SRCS	= $(wildcard ../lib/paho.mqtt.c/src/*.c)
#MQTT_OBJS	= $(patsubst $(MQTT_SRC_DIR)%.c, $(OBJ_DIR)%.o, $(MQTT_SRCS))

INCLUDES 	= -I/usr/include/postgresql \
		  -I$(INC_DIR) \
		  -I../lib/paho.mqtt.c/src

TARGET 		= $(BIN_DIR)/gateway
#OBJS		= $(wildcard $(OBJ_DIR)/*.o)
#
SRCS		= $(wildcard $(SRC_DIR)/*.c)
OBJS		= $(patsubst $(SRC_DIR)%.c, $(OBJ_DIR)%.o, $(SRCS))
#


$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(MQTT_INCLUDES) $(OBJS) -o $(TARGET) $(LFLAGS)

$(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -c -MD $(CFLAGS) $(INCLUDES) $< -o $@

-include $(OBJ_DIR)/*.d

.PHONY: clean print

clean :
	rm -f $(BIN_DIR)/* $(OBJ_DIR)/*

print :
	$(info $$OBJS is [${OBJS}])
