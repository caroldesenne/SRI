import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.XYChart;
import javafx.stage.Stage;

public class delayChartConstructor extends Application {

	public static final String filename = "/Users/carol/Documents/code/delayMap";
	public static final String pattern = "^(\\d+)\\s:\\s(\\d+)$";
	public static final double FRACTION = 0.9; // fraction of occurences to be taken into account in the graphic
	public static Map<Integer,Integer> delayOccurences = new HashMap<Integer,Integer>();

	/**
	 * TODO COMMENT
	 */
	@Override public void start(Stage stage) {
		// General chart configuration
		stage.setTitle("Delay-Occurences Chart");
		final CategoryAxis xAxis = new CategoryAxis();
		final NumberAxis yAxis = new NumberAxis();
		final BarChart<String,Number> chart = new BarChart<String,Number>(xAxis,yAxis);
		chart.setTitle("Record's Delay Distribution");
		xAxis.setLabel("Delay");
		yAxis.setLabel("Occurences");
		// Series
		XYChart.Series<String,Number> series = new XYChart.Series<String,Number>();
		constructSeries(series,FRACTION);
		// Chart
		Scene scene = new Scene(chart,800,600);
		chart.getData().add(series);
		stage.setScene(scene);
		stage.show();
	}

	// TODO COMMENT
	public static void constructSeries(XYChart.Series<String,Number> series, double fraction) {
		int[] info = readMapFromFile(filename);
		int max = info[0];
		int total = info[1];
		Integer occurences;
		int countOccurences = 0;
		for(int i = 1; i < max && countOccurences < fraction*total; i++) {
			occurences = delayOccurences.get(i);
			if(occurences == null) {
				series.getData().add(new XYChart.Data<String,Number>(Integer.toString(i),0));
			} else {
				series.getData().add(new XYChart.Data<String,Number>(Integer.toString(i),occurences));
				countOccurences += occurences;
			}
		}
	}

	/**
	 *
	 * TODO COMMENT
	 */
	public static int[] readMapFromFile(String path)  {
		// information about data
		int[] info = new int[2];
		info[0] = 0;						// corresponds to max delay value
		info[1] = 0;						// corresponds to total number of occurences
 		// Matcher for file lines
		Pattern p = Pattern.compile(pattern);
		Matcher m = null;
		// read from delayMap file
		int delay=0;
		int occurences=0;
		BufferedReader buffer = openFile(path);
		String line = null;
		try {
			while((line = buffer.readLine()) != null) {
				m = p.matcher(line);
				if(m.find()) {
					// put information from file in the map
					delay = Integer.parseInt(m.group(1));
					occurences = Integer.parseInt(m.group(2));
					delayOccurences.put(delay,occurences);
					if(delay > info[0])
						info[0] = delay;
					info[1] += occurences;
				}
			}
		} catch(IOException e) {
			System.err.println(e.getMessage());
			System.err.println("Problem reading from file");
		}
		return info;
	}

	public static void main(String[] args) {
		launch(args);
	}

	/** 
	 * Open a file and return its respective BufferedReader
	 *
	 * @param path to file to be opened
	 * @return buffer to read the log file explicited in path
	 */
	public static BufferedReader openFile(String path) {
		FileReader fr = null;
		try {
			fr = new FileReader(path);
		} catch(IOException e) {
			System.err.println(e.getMessage());
			System.err.println("Couldn't open the log file: "+path);
		}
		return new BufferedReader(fr);
	}
}
