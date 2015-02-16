package me.StevenLawson.TotalFreedomMod.World;

import static java.lang.System.arraycopy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;
import org.bukkit.Bukkit;
import org.bukkit.Location;
import org.bukkit.Material;
import org.bukkit.World;
import org.bukkit.generator.BlockPopulator;
import org.bukkit.generator.ChunkGenerator;

@SuppressWarnings("deprecation")
public class CleanroomChunkGenerator extends ChunkGenerator
{
    private static final Logger log = Bukkit.getLogger();
    private short[] layer;
    private byte[] layerDataValues;

    public CleanroomChunkGenerator()
    {
        this("64,stone");
    }

    public CleanroomChunkGenerator(String id)
    {
        if (id != null)
        {
            try
            {
                int y = 0;

                layer = new short[128];
                layerDataValues = null;

                if ((id.length() > 0) && (id.charAt(0) == '.'))
                {
                    id = id.substring(1);
                }
                else
                {
                    layer[y++] = (short) Material.BEDROCK.getId();
                }

                if (id.length() > 0)
                {
                    String tokens[] = id.split("[,]");

                    if ((tokens.length % 2) != 0)
                    {
                        throw new Exception();
                    }

                    for (int i = 0; i < tokens.length; i += 2)
                    {
                        int height = Integer.parseInt(tokens[i]);
                        if (height <= 0)
                        {
                            log.warning("[CleanroomGenerator] Invalid height '" + tokens[i] + "'. Using 64 instead.");
                            height = 64;
                        }

                        String materialTokens[] = tokens[i + 1].split("[:]", 2);
                        byte dataValue = 0;
                        if (materialTokens.length == 2)
                        {
                            try
                            {
                                dataValue = Byte.parseByte(materialTokens[1]);
                            }
                            catch (Exception e)
                            {
                                log.warning("[CleanroomGenerator] Invalid Data Value '" + materialTokens[1] + "'. Defaulting to 0.");
                                dataValue = 0;
                            }
                        }
                        Material mat = Material.matchMaterial(materialTokens[0]);
                        if (mat == null)
                        {
                            try
                            {
                                mat = Material.getMaterial(Integer.parseInt(materialTokens[0]));
                            }
                            catch (Exception e)
                            {
                            }

                            if (mat == null)
                            {
                                log.warning("[CleanroomGenerator] Invalid Block ID '" + materialTokens[0] + "'. Defaulting to stone.");
                                mat = Material.STONE;
                            }
                        }

                        if (!mat.isBlock())
                        {
                            log.warning("[CleanroomGenerator] Error, '" + materialTokens[0] + "' is not a block. Defaulting to stone.");
                            mat = Material.STONE;
                        }

                        if (y + height > layer.length)
                        {
                            short[] newLayer = new short[Math.max(y + height, layer.length * 2)];
                            arraycopy(layer, 0, newLayer, 0, y);
                            layer = newLayer;
                            if (layerDataValues != null)
                            {
                                byte[] newLayerDataValues = new byte[Math.max(y + height, layerDataValues.length * 2)];
                                arraycopy(layerDataValues, 0, newLayerDataValues, 0, y);
                                layerDataValues = newLayerDataValues;
                            }
                        }

                        Arrays.fill(layer, y, y + height, (short) mat.getId());
                        if (dataValue != 0)
                        {
                            if (layerDataValues == null)
                            {
                                layerDataValues = new byte[layer.length];
                            }
                            Arrays.fill(layerDataValues, y, y + height, dataValue);
                        }
                        y += height;
                    }
                }

                if (layer.length > y)
                {
                    short[] newLayer = new short[y];
                    arraycopy(layer, 0, newLayer, 0, y);
                    layer = newLayer;
                }
                if (layerDataValues != null && layerDataValues.length > y)
                {
                    byte[] newLayerDataValues = new byte[y];
                    arraycopy(layerDataValues, 0, newLayerDataValues, 0, y);
                    layerDataValues = newLayerDataValues;
                }
            }
            catch (Exception e)
            {
                log.severe("[CleanroomGenerator] Error parsing CleanroomGenerator ID '" + id + "'. using defaults '64,1': " + e.toString());
                e.printStackTrace();
                layerDataValues = null;
                layer = new short[65];
                layer[0] = (short) Material.BEDROCK.getId();
                Arrays.fill(layer, 1, 65, (short) Material.STONE.getId());
            }
        }
        else
        {
            layerDataValues = null;
            layer = new short[65];
            layer[0] = (short) Material.BEDROCK.getId();
            Arrays.fill(layer, 1, 65, (short) Material.STONE.getId());
        }
    }

    @Override
    public short[][] generateExtBlockSections(World world, Random random, int x, int z, BiomeGrid biomes)
    {
        int maxHeight = world.getMaxHeight();
        if (layer.length > maxHeight)
        {
            log.warning("[CleanroomGenerator] Error, chunk height " + layer.length + " is greater than the world max height (" + maxHeight + "). Trimming to world max height.");
            short[] newLayer = new short[maxHeight];
            arraycopy(layer, 0, newLayer, 0, maxHeight);
            layer = newLayer;
        }
        short[][] result = new short[maxHeight / 16][];
        for (int i = 0; i < layer.length; i += 16)
        {
            result[i >> 4] = new short[4096];
            for (int y = 0; y < Math.min(16, layer.length - i); y++)
            {
                Arrays.fill(result[i >> 4], y * 16 * 16, (y + 1) * 16 * 16, layer[i + y]);
            }
        }

        return result;
    }

    @Override
    public List<BlockPopulator> getDefaultPopulators(World world)
    {
        if (layerDataValues != null)
        {
            return Arrays.asList((BlockPopulator) new CleanroomBlockPopulator(layerDataValues));
        }
        else
        {
            return new ArrayList<BlockPopulator>();
        }
    }

    @Override
    public Location getFixedSpawnLocation(World world, Random random)
    {
        if (!world.isChunkLoaded(0, 0))
        {
            world.loadChunk(0, 0);
        }

        if ((world.getHighestBlockYAt(0, 0) <= 0) && (world.getBlockAt(0, 0, 0).getType() == Material.AIR))
        {
            return new Location(world, 0, 64, 0);
        }

        return new Location(world, 0, world.getHighestBlockYAt(0, 0), 0);
    }
}
