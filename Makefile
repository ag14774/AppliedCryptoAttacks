class_d=bin
source_d=src
JFLAGS=-d $(class_d) -sourcepath $(source_d) -Xlint:all
JC=javac

classpath:=$(class_d):

# Re-export the CLASSPATH.
export CLASSPATH:=$(classpath)

.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
	./src/IAttacker.java \
	./src/AbstractAttacker.java \
	./src/FaultAttacker.java \
	./src/Launcher.java \
	./src/OAEPAttacker.java \
	./src/PowerAttacker.java \
	./src/TimeAttacker.java

default: classes

$(class_d):
	mkdir $(class_d)

classes: $(class_d) $(CLASSES:.java=.class)

jar:
	$(classes)
	jar cvfm Launcher.jar manifest -C bin/ .

clean:
	rm -rf $(class_d)/*
