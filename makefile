LDLIBS += -lpcap

all: deauth

airodump: deauth.cpp

clean:
	rm -f deauth *.o