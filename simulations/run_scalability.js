/* Cooja simulation script for scalability testing.
 * Run via: Tools -> Simulation script editor -> Load -> Run
 *
 * Tests: 1, 10, 25, 50, 100 motes
 * Measures: simulation time for all motes to complete MSG_1
 * Output: printed to log, parsed by scripts/parse_scalability.py
 */

TIMEOUT(300000); /* 5 minute max per run */

var mote_counts = [1, 10, 25, 50, 100];
var results = [];

for (var r = 0; r < mote_counts.length; r++) {
    var n = mote_counts[r];
    var completed = 0;
    var start_time = 0;
    var end_time = 0;

    log.log("=== SCALABILITY TEST: " + n + " motes ===\n");

    /* Reset simulation */
    sim.setSimulationTime(0);

    /* Add n motes at random positions */
    for (var i = 0; i < n; i++) {
        var mote = sim.getMoteTypes()[0].generateMote(sim);
        mote.getInterfaces().getPosition().setCoordinates(
            Math.random() * 100,
            Math.random() * 100,
            0
        );
        sim.addMote(mote);
    }

    start_time = sim.getSimulationTimeMillis();

    /* Run until all motes print "Done" */
    while (completed < n) {
        YIELD();
        var msg = msg;
        if (msg.contains("=== Done ===")) {
            completed++;
            if (completed == n) {
                end_time = sim.getSimulationTimeMillis();
            }
        }
        if (sim.getSimulationTimeMillis() - start_time > 60000) {
            log.log("TIMEOUT waiting for " + n + " motes\n");
            break;
        }
    }

    var duration = end_time - start_time;
    log.log("RESULT: motes=" + n +
            " duration_ms=" + duration +
            " per_mote_ms=" + (duration/n) + "\n");

    /* Remove all motes for next run */
    var motes = sim.getMotes();
    for (var i = 0; i < motes.length; i++) {
        sim.removeMote(motes[i]);
    }
}

log.log("=== ALL SCALABILITY TESTS COMPLETE ===\n");
KILL();
