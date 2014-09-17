package no.difi;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args ) throws Exception
    {

        VirksomhetGenerator generator = new VirksomhetGenerator();
        generator.generateRot();
        generator.generateIntermediate();
        generator.generateVirksomhet("987654321");

    }
}
