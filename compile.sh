#!/bin/bash

gcc -Wall -Wextra -o build/audioc.o audiocArgs.c circularBuffer.c configureSndcard.c easyUDPSockets.c audioc_light.c
