package me.StevenLawson.TotalFreedomMod.Config;

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import me.StevenLawson.TotalFreedomMod.TFM_Util;
import net.minecraft.util.org.apache.commons.lang3.exception.ExceptionUtils;
import org.bukkit.configuration.InvalidConfigurationException;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.Plugin;

public class TFM_Config extends YamlConfiguration
{
    private final Plugin plugin;
    private final File configFile;
    private final boolean copyDefaults;

    public TFM_Config(Plugin plugin, String fileName, boolean copyDefaults)
    {
        this(plugin, TFM_Util.getPluginFile(plugin, fileName), copyDefaults);
    }

    public TFM_Config(Plugin plugin, File file, boolean copyDefaults)
    {
        this.plugin = plugin;
        this.configFile = file;
        this.copyDefaults = copyDefaults;
    }

    public boolean exists()
    {
        return configFile.exists();
    }

    public void save()
    {
        try
        {
            super.save(configFile);
        }
        catch (Exception ex)
        {
            plugin.getLogger().severe("Could not save configuration file: " + configFile.getName());
            plugin.getLogger().severe(ExceptionUtils.getStackTrace(ex));
        }
    }

    public void load()
    {
        try
        {
            if (copyDefaults)
            {
                if (!configFile.exists())
                {
                    configFile.getParentFile().mkdirs();
                    try
                    {
                        TFM_Util.copy(plugin.getResource(configFile.getName()), configFile);
                    }
                    catch (IOException ex)
                    {
                        plugin.getLogger().severe("Could not write default configuration file: " + configFile.getName());
                        plugin.getLogger().severe(ExceptionUtils.getStackTrace(ex));
                    }
                    plugin.getLogger().info("Installed default configuration " + configFile.getName());
                }

                super.addDefaults(getDefaultConfig());
            }

            if (configFile.exists())
            {
                super.load(configFile);
            }
        }
        catch (Exception ex)
        {
            plugin.getLogger().severe("Could not load configuration file: " + configFile.getName());
            plugin.getLogger().severe(ExceptionUtils.getStackTrace(ex));
        }
    }

    public YamlConfiguration getConfig()
    {
        return this;
    }

    public YamlConfiguration getDefaultConfig()
    {
        final YamlConfiguration DEFAULT_CONFIG = new YamlConfiguration();
        try
        {
            final InputStreamReader isr = new InputStreamReader(plugin.getResource(configFile.getName()));
            DEFAULT_CONFIG.load(isr);
            isr.close();
        }
        catch (IOException ex)
        {
            plugin.getLogger().severe("Could not load default configuration: " + configFile.getName());
            plugin.getLogger().severe(ExceptionUtils.getStackTrace(ex));
            return null;
        }
        catch (InvalidConfigurationException ex)
        {
            plugin.getLogger().severe("Could not load default configuration: " + configFile.getName());
            plugin.getLogger().severe(ExceptionUtils.getStackTrace(ex));
            return null;
        }
        return DEFAULT_CONFIG;
    }
}
