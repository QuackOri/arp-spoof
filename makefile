LDLIBS=-lpcap
CC=g++
CFLAGS=-I./include
SRC_DIR=./src
OBJ_DIR=./obj
INCLUDE_DIR=./include

# 소스 파일
SRCS=$(SRC_DIR)/main.cpp $(SRC_DIR)/arphdr.cpp $(SRC_DIR)/ethhdr.cpp $(SRC_DIR)/ip.cpp $(SRC_DIR)/mac.cpp

# 객체 파일
OBJS=$(OBJ_DIR)/main.o $(OBJ_DIR)/arphdr.o $(OBJ_DIR)/ethhdr.o $(OBJ_DIR)/ip.o $(OBJ_DIR)/mac.o

# 최종 실행 파일
TARGET=send-arp-test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CC) $(CFLAGS) -c $< -o $@

# 디렉터리가 없다면 생성
$(OBJS): | $(OBJ_DIR)

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

